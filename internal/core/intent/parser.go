// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package intent

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	intentStartRE  = regexp.MustCompile(`^intent\s+"([^"]+)"\s+\{$`)
	namedBlockRE   = regexp.MustCompile(`^(rule|simulation)\s+"([^"]+)"\s+\{$`)
	simpleBlockRE  = regexp.MustCompile(`^(risk_behavior|runtime|expect)\s+\{$`)
	assignmentRE   = regexp.MustCompile(`^([A-Za-z_]+)\s*=\s*(.+)$`)
	riskBehaviorRE = regexp.MustCompile(`^when\s+"([^"]+)"\s+is\s+"([^"]+)"\s+then\s+"([^"]+)"$`)
	inlineExpectRE = regexp.MustCompile(`^expect\s+\{\s*effect\s*=\s*"([^"]+)"\s*\}$`)
	quotedStringRE = regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"`)
)

func ParseFile(path string) (*Card, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var card *Card
	var stack []string
	var listKey string
	var listValues []string
	lineNo := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		if listKey != "" {
			listValues = append(listValues, quotedStrings(line)...)
			if strings.Contains(line, "]") {
				if err := assignList(card, current(stack), listKey, listValues); err != nil {
					return nil, parseError(path, lineNo, err)
				}
				listKey = ""
				listValues = nil
			}
			continue
		}

		if match := inlineExpectRE.FindStringSubmatch(line); match != nil {
			if err := assignScalar(card, "expect", "effect", match[1]); err != nil {
				return nil, parseError(path, lineNo, err)
			}
			continue
		}

		if match := intentStartRE.FindStringSubmatch(line); match != nil {
			if card != nil {
				return nil, parseError(path, lineNo, fmt.Errorf("multiple intent blocks are not supported"))
			}
			card = &Card{ID: match[1], SourcePath: path}
			stack = append(stack, "intent")
			continue
		}
		if card == nil {
			return nil, parseError(path, lineNo, fmt.Errorf("expected intent block"))
		}

		if match := namedBlockRE.FindStringSubmatch(line); match != nil {
			switch match[1] {
			case "rule":
				card.Rules = append(card.Rules, Rule{Name: match[2]})
			case "simulation":
				card.Simulations = append(card.Simulations, Simulation{Name: match[2]})
			}
			stack = append(stack, match[1])
			continue
		}

		if match := simpleBlockRE.FindStringSubmatch(line); match != nil {
			stack = append(stack, match[1])
			continue
		}

		if line == "}" {
			if len(stack) == 0 {
				return nil, parseError(path, lineNo, fmt.Errorf("unmatched closing brace"))
			}
			stack = stack[:len(stack)-1]
			continue
		}

		if current(stack) == "risk_behavior" {
			match := riskBehaviorRE.FindStringSubmatch(line)
			if match == nil {
				return nil, parseError(path, lineNo, fmt.Errorf("invalid risk_behavior line"))
			}
			card.Risk = append(card.Risk, RiskBehavior{RiskType: match[1], Tier: match[2], Effect: match[3]})
			continue
		}

		match := assignmentRE.FindStringSubmatch(line)
		if match == nil {
			return nil, parseError(path, lineNo, fmt.Errorf("unsupported syntax %q", line))
		}
		key, raw := match[1], strings.TrimSpace(match[2])
		if strings.HasPrefix(raw, "[") {
			values := quotedStrings(raw)
			if strings.Contains(raw, "]") {
				if err := assignList(card, current(stack), key, values); err != nil {
					return nil, parseError(path, lineNo, err)
				}
			} else {
				listKey = key
				listValues = values
			}
			continue
		}
		value, err := parseScalar(raw)
		if err != nil {
			return nil, parseError(path, lineNo, err)
		}
		if err := assignScalar(card, current(stack), key, value); err != nil {
			return nil, parseError(path, lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if card == nil {
		return nil, fmt.Errorf("%s: no intent block found", path)
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("%s: unclosed block %q", path, stack[len(stack)-1])
	}
	return card, nil
}

func assignScalar(card *Card, block, key, value string) error {
	switch block {
	case "intent":
		switch key {
		case "version":
			card.Version = value
		case "owner":
			card.Owner = value
		case "type":
			card.Type = value
		case "target":
			card.Target = value
		case "stage":
			card.Stage = value
		case "profile":
			card.Profile = value
		case "risk_recipe":
			card.RiskRecipe = value
		default:
			return fmt.Errorf("unknown intent field %q", key)
		}
	case "rule":
		if len(card.Rules) == 0 {
			return fmt.Errorf("rule field outside rule block")
		}
		rule := &card.Rules[len(card.Rules)-1]
		switch key {
		case "effect":
			rule.Effect = value
		case "subject":
			rule.Subject = value
		case "action":
			rule.Action = value
		case "resource":
			rule.Resource = value
		default:
			return fmt.Errorf("unknown rule field %q", key)
		}
	case "runtime":
		switch key {
		case "allowed":
			card.Runtime.Allowed = value == "true"
		case "max_ttl":
			card.Runtime.MaxTTL = value
		case "max_scope":
			card.Runtime.MaxScope = value
		default:
			return fmt.Errorf("unknown runtime field %q", key)
		}
	case "expect":
		if key != "effect" {
			return fmt.Errorf("unknown expect field %q", key)
		}
		if len(card.Simulations) == 0 {
			return fmt.Errorf("expect field outside simulation block")
		}
		card.Simulations[len(card.Simulations)-1].ExpectEffect = value
	default:
		return fmt.Errorf("field %q is not valid inside %q", key, block)
	}
	return nil
}

func assignList(card *Card, block, key string, values []string) error {
	switch block {
	case "rule":
		if key != "only_when" {
			return fmt.Errorf("unknown rule list %q", key)
		}
		if len(card.Rules) == 0 {
			return fmt.Errorf("only_when outside rule block")
		}
		card.Rules[len(card.Rules)-1].OnlyWhen = values
	case "intent":
		if key != "prohibit" {
			return fmt.Errorf("unknown intent list %q", key)
		}
		card.Prohibit = values
	case "runtime":
		if key != "actions" {
			return fmt.Errorf("unknown runtime list %q", key)
		}
		card.Runtime.Actions = values
	case "simulation":
		if key != "given" {
			return fmt.Errorf("unknown simulation list %q", key)
		}
		if len(card.Simulations) == 0 {
			return fmt.Errorf("given outside simulation block")
		}
		card.Simulations[len(card.Simulations)-1].Given = values
	default:
		return fmt.Errorf("list %q is not valid inside %q", key, block)
	}
	return nil
}

func current(stack []string) string {
	if len(stack) == 0 {
		return ""
	}
	return stack[len(stack)-1]
}

func parseScalar(raw string) (string, error) {
	switch raw {
	case "true", "false":
		return raw, nil
	}
	if strings.HasPrefix(raw, `"""`) {
		return "", fmt.Errorf("multiline strings are not supported in Slice 1 parser")
	}
	if strings.HasPrefix(raw, `"`) {
		return strconv.Unquote(raw)
	}
	return "", fmt.Errorf("expected quoted string or boolean, got %q", raw)
}

func quotedStrings(line string) []string {
	matches := quotedStringRE.FindAllStringSubmatch(line, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		value, err := strconv.Unquote(`"` + match[1] + `"`)
		if err == nil {
			values = append(values, value)
		}
	}
	return values
}

func parseError(path string, lineNo int, err error) error {
	return fmt.Errorf("%s:%d: %w", path, lineNo, err)
}
