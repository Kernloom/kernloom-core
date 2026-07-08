// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type schemaDocumentTarget struct {
	Path       string
	SchemaName string
	Required   bool
}

func validateSchemaFiles(coreRegistryPath string, names []string) error {
	for _, name := range names {
		path := filepath.Join(coreRegistryPath, "schemas", name)
		schema, err := loadJSONSchema(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(fmt.Sprint(schema["$schema"])) == "" {
			return fmt.Errorf("schema_invalid: %s: missing $schema", path)
		}
		if schemaType := strings.TrimSpace(fmt.Sprint(schema["type"])); schemaType != "object" {
			return fmt.Errorf("schema_invalid: %s: type must be object", path)
		}
		if err := validateSupportedSchemaKeywords(path, schema, "$"); err != nil {
			return err
		}
	}
	return nil
}

func validateRegistryDocuments(coreRegistryPath, enterpriseRegistryPath string) error {
	targets := []schemaDocumentTarget{
		{Path: filepath.Join(coreRegistryPath, "core", "authoring_catalog.yaml"), SchemaName: "authoring-catalog.schema.json", Required: true},
		{Path: filepath.Join(coreRegistryPath, "core", "capability_catalog.yaml"), SchemaName: "capability-catalog.schema.json", Required: true},
		{Path: filepath.Join(coreRegistryPath, "core", "compiler_rule_catalog.yaml"), SchemaName: "compiler-rule-catalog.schema.json", Required: true},
	}
	for _, definition := range supplementalCatalogDefinitions {
		targets = append(targets, schemaDocumentTarget{
			Path:       filepath.Join(coreRegistryPath, definition.Path),
			SchemaName: "supplemental-catalog.schema.json",
			Required:   definition.Required,
		})
	}
	if strings.TrimSpace(enterpriseRegistryPath) != "" {
		targets = append(targets, schemaDocumentTarget{
			Path:       filepath.Join(enterpriseRegistryPath, "bindings", "adapter_bindings.yaml"),
			SchemaName: "adapter-binding.schema.json",
			Required:   true,
		})
	}
	for _, target := range targets {
		if err := validateRegistryDocument(coreRegistryPath, target); err != nil {
			return err
		}
	}
	return nil
}

func validateRegistryDocument(coreRegistryPath string, target schemaDocumentTarget) error {
	if _, err := os.Stat(target.Path); err != nil {
		if os.IsNotExist(err) && !target.Required {
			return nil
		}
		return err
	}
	schemaPath := filepath.Join(coreRegistryPath, "schemas", target.SchemaName)
	schema, err := loadJSONSchema(schemaPath)
	if err != nil {
		return err
	}
	value, err := loadYAMLValue(target.Path)
	if err != nil {
		return err
	}
	if err := validateSchemaValue(schema, value, "$"); err != nil {
		return fmt.Errorf("schema_validation_failed: %s against %s: %w", target.Path, target.SchemaName, err)
	}
	return nil
}

func loadJSONSchema(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("schema_missing: %s", path)
		}
		return nil, err
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("schema_invalid: %s: %w", path, err)
	}
	return schema, nil
}

func loadYAMLValue(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return normalizeYAMLValue(value), nil
}

func normalizeYAMLValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, child := range typed {
			out[key] = normalizeYAMLValue(child)
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for key, child := range typed {
			out[fmt.Sprint(key)] = normalizeYAMLValue(child)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, child := range typed {
			out = append(out, normalizeYAMLValue(child))
		}
		return out
	default:
		return value
	}
}

func validateSupportedSchemaKeywords(schemaPath string, schema map[string]any, at string) error {
	for key, value := range schema {
		switch key {
		case "$schema", "$id", "title", "description", "type", "required", "properties", "additionalProperties", "items", "enum", "pattern", "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum":
		default:
			return fmt.Errorf("schema_invalid: %s: unsupported keyword %q at %s", schemaPath, key, at)
		}
		switch key {
		case "properties":
			properties, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("schema_invalid: %s: properties at %s must be an object", schemaPath, at)
			}
			for name, raw := range properties {
				child, ok := raw.(map[string]any)
				if !ok {
					return fmt.Errorf("schema_invalid: %s: property %q at %s must be an object", schemaPath, name, at)
				}
				if err := validateSupportedSchemaKeywords(schemaPath, child, at+".properties."+name); err != nil {
					return err
				}
			}
		case "items":
			child, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("schema_invalid: %s: items at %s must be an object", schemaPath, at)
			}
			if err := validateSupportedSchemaKeywords(schemaPath, child, at+".items"); err != nil {
				return err
			}
		case "additionalProperties":
			if _, ok := value.(bool); ok {
				continue
			}
			child, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("schema_invalid: %s: additionalProperties at %s must be a boolean or object", schemaPath, at)
			}
			if err := validateSupportedSchemaKeywords(schemaPath, child, at+".additionalProperties"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSchemaValue(schema map[string]any, value any, at string) error {
	if rawType, ok := schema["type"]; ok {
		if err := validateSchemaType(rawType, value, at); err != nil {
			return err
		}
	}
	if rawEnum, ok := schema["enum"]; ok {
		enumValues, ok := rawEnum.([]any)
		if !ok {
			return fmt.Errorf("%s: schema enum must be an array", at)
		}
		matched := false
		for _, enumValue := range enumValues {
			if jsonValuesEqual(value, enumValue) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value %q is not one of %s", at, fmt.Sprint(value), enumList(enumValues))
		}
	}
	if rawPattern, ok := schema["pattern"]; ok {
		pattern, ok := rawPattern.(string)
		if !ok {
			return fmt.Errorf("%s: schema pattern must be a string", at)
		}
		text, ok := value.(string)
		if ok {
			matched, err := regexp.MatchString(pattern, text)
			if err != nil {
				return fmt.Errorf("%s: schema pattern %q is invalid: %w", at, pattern, err)
			}
			if !matched {
				return fmt.Errorf("%s: value %q does not match pattern %q", at, text, pattern)
			}
		}
	}
	if err := validateStringBounds(schema, value, at); err != nil {
		return err
	}
	if err := validateNumberBounds(schema, value, at); err != nil {
		return err
	}
	if err := validateObjectSchema(schema, value, at); err != nil {
		return err
	}
	if err := validateArraySchema(schema, value, at); err != nil {
		return err
	}
	return nil
}

func validateSchemaType(rawType any, value any, at string) error {
	types, err := schemaTypes(rawType)
	if err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}
	for _, schemaType := range types {
		if valueMatchesSchemaType(value, schemaType) {
			return nil
		}
	}
	return fmt.Errorf("%s: expected type %s, got %s", at, strings.Join(types, "|"), valueTypeName(value))
}

func schemaTypes(rawType any) ([]string, error) {
	switch typed := rawType.(type) {
	case string:
		return []string{typed}, nil
	case []any:
		types := make([]string, 0, len(typed))
		for _, value := range typed {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("schema type array must contain strings")
			}
			types = append(types, text)
		}
		return types, nil
	default:
		return nil, fmt.Errorf("schema type must be a string or string array")
	}
}

func valueMatchesSchemaType(value any, schemaType string) bool {
	switch schemaType {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		return isNumber(value)
	case "integer":
		return isInteger(value)
	case "null":
		return value == nil
	default:
		return false
	}
}

func validateObjectSchema(schema map[string]any, value any, at string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if rawRequired, ok := schema["required"]; ok {
		required, ok := rawRequired.([]any)
		if !ok {
			return fmt.Errorf("%s: schema required must be an array", at)
		}
		for _, rawName := range required {
			name, ok := rawName.(string)
			if !ok {
				return fmt.Errorf("%s: schema required entries must be strings", at)
			}
			if _, exists := object[name]; !exists {
				return fmt.Errorf("%s: missing required property %q", at, name)
			}
		}
	}
	properties := map[string]map[string]any{}
	if rawProperties, ok := schema["properties"]; ok {
		rawMap, ok := rawProperties.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: schema properties must be an object", at)
		}
		for name, rawSchema := range rawMap {
			child, ok := rawSchema.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: schema property %q must be an object", at, name)
			}
			properties[name] = child
		}
	}
	for name, child := range properties {
		if childValue, exists := object[name]; exists {
			if err := validateSchemaValue(child, childValue, at+"."+name); err != nil {
				return err
			}
		}
	}
	if rawAdditional, ok := schema["additionalProperties"]; ok {
		switch additional := rawAdditional.(type) {
		case bool:
			if !additional {
				for name := range object {
					if _, known := properties[name]; !known {
						return fmt.Errorf("%s: additional property %q is not allowed", at, name)
					}
				}
			}
		case map[string]any:
			for name, childValue := range object {
				if _, known := properties[name]; known {
					continue
				}
				if err := validateSchemaValue(additional, childValue, at+"."+name); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("%s: schema additionalProperties must be a boolean or object", at)
		}
	}
	return nil
}

func validateArraySchema(schema map[string]any, value any, at string) error {
	array, ok := value.([]any)
	if !ok {
		return nil
	}
	if minItems, ok, err := optionalInt(schema, "minItems"); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if ok && len(array) < minItems {
		return fmt.Errorf("%s: expected at least %d items, got %d", at, minItems, len(array))
	}
	if maxItems, ok, err := optionalInt(schema, "maxItems"); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if ok && len(array) > maxItems {
		return fmt.Errorf("%s: expected at most %d items, got %d", at, maxItems, len(array))
	}
	rawItems, ok := schema["items"]
	if !ok {
		return nil
	}
	itemSchema, ok := rawItems.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: schema items must be an object", at)
	}
	for i, item := range array {
		if err := validateSchemaValue(itemSchema, item, at+"["+strconv.Itoa(i)+"]"); err != nil {
			return err
		}
	}
	return nil
}

func validateStringBounds(schema map[string]any, value any, at string) error {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	if minLength, ok, err := optionalInt(schema, "minLength"); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if ok && len(text) < minLength {
		return fmt.Errorf("%s: expected length at least %d, got %d", at, minLength, len(text))
	}
	if maxLength, ok, err := optionalInt(schema, "maxLength"); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if ok && len(text) > maxLength {
		return fmt.Errorf("%s: expected length at most %d, got %d", at, maxLength, len(text))
	}
	return nil
}

func validateNumberBounds(schema map[string]any, value any, at string) error {
	number, ok := numberValue(value)
	if !ok {
		return nil
	}
	if minimum, ok, err := optionalFloat(schema, "minimum"); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if ok && number < minimum {
		return fmt.Errorf("%s: expected value at least %v, got %v", at, minimum, number)
	}
	if maximum, ok, err := optionalFloat(schema, "maximum"); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if ok && number > maximum {
		return fmt.Errorf("%s: expected value at most %v, got %v", at, maximum, number)
	}
	return nil
}

func optionalInt(schema map[string]any, key string) (int, bool, error) {
	raw, ok := schema[key]
	if !ok {
		return 0, false, nil
	}
	number, ok := numberValue(raw)
	if !ok || math.Trunc(number) != number {
		return 0, false, fmt.Errorf("schema %s must be an integer", key)
	}
	return int(number), true, nil
}

func optionalFloat(schema map[string]any, key string) (float64, bool, error) {
	raw, ok := schema[key]
	if !ok {
		return 0, false, nil
	}
	number, ok := numberValue(raw)
	if !ok {
		return 0, false, fmt.Errorf("schema %s must be a number", key)
	}
	return number, true, nil
}

func isNumber(value any) bool {
	_, ok := numberValue(value)
	return ok
}

func isInteger(value any) bool {
	number, ok := numberValue(value)
	return ok && math.Trunc(number) == number
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case float32:
		return float64(typed), true
	case float64:
		return typed, true
	default:
		return 0, false
	}
}

func jsonValuesEqual(left, right any) bool {
	if reflect.DeepEqual(left, right) {
		return true
	}
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func valueTypeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	default:
		if isInteger(value) {
			return "integer"
		}
		if isNumber(value) {
			return "number"
		}
		return fmt.Sprintf("%T", value)
	}
}

func enumList(values []any) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%q", fmt.Sprint(value)))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
