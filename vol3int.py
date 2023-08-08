from volatility3.framework import contexts
from volatility3.plugins.windows.registry import registryapi
import os
from datetime import datetime  # Import datetime module

def read_keys_from_file(file_path):
    with open(file_path, "r") as f:
        lines = f.readlines()
    return [line.strip() for line in lines]

def identify_modified_keys(admin_editable_keys, system_only_keys):
    modified_keys = []
    # Placeholder logic: Compare admin_editable_keys with system_only_keys
    # to identify keys that are modified from default state
    for key in admin_editable_keys:
        if key in system_only_keys:
            modified_keys.append(key)
    return modified_keys

def analyze_permissions(registry, key):
    # Placeholder logic: Retrieve permissions info for the key using Volatility 3's registry API
    permissions_info = registry.get_key(key).get_acl()
    return permissions_info

def identify_permission_changed_keys(keys, registry):
    permission_changed_keys = []
    for key in keys:
        permissions_info = analyze_permissions(registry, key)
        # Placeholder logic: Determine if permissions_info indicates a permission change
        # Example: Check if there's a change from admin to SYSTEM or vice versa
        if permissions_changed:  # Replace with your actual condition/logic
            permission_changed_keys.append(key)
    return permission_changed_keys

def sort_keys_by_timestamp(keys, timestamp_dict):
    sorted_keys = sorted(keys, key=lambda key: timestamp_dict.get(key, 0), reverse=True)
    return sorted_keys

def generate_and_write_report(keys):
    with open("reports/permissions_changed_report.txt", "w") as f:
        for key in keys:
            f.write(f"{key}\n")

def main():
    # Configure Volatility 3 context
    context_path = "/path/to/Volatility3/volatility3/plugins/overlays/windows/context.yaml"
    context = contexts.Context(context_path)

    # Set memory image and configuration
    memory_image_path = "/path/to/memory.raw"
    volatility_config_path = "/path/to/Volatility3/volatility3/plugins/overlays/windows/windows.json"
    context.config['memory_file'] = memory_image_path
    context.config['location'] = volatility_config_path

    # Initialize the registry API
    registry = registryapi.RegistryApi(context)

    admin_editable_keys = read_keys_from_file("input/admin_editable_keys.txt")
    system_only_keys = read_keys_from_file("input/system_only_keys.txt")
    modified_keys = identify_modified_keys(admin_editable_keys, system_only_keys)
    
    permission_changed_keys = identify_permission_changed_keys(modified_keys, registry)
    
    timestamp_dict = {}  # Placeholder: Replace with actual timestamp dictionary
    
    ordered_keys = sort_keys_by_timestamp(permission_changed_keys, timestamp_dict)
    
    generate_and_write_report(ordered_keys)

if __name__ == "__main__":
    main()
  
