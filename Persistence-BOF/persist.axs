var metadata = {
    name: "Persistence-BOF",
    description: "BOFs for Windows persistence mechanisms"
};

/// COMMANDS

// Registry Run Keys Persistence
var cmd_persist_registry = ax.create_command("registry-run", "Add/Remove registry run key persistence", "persist registry-run --add MyApp C:\\path\\to\\app.exe");
cmd_persist_registry.addArgBool("--add", "Add persistence entry");
cmd_persist_registry.addArgBool("--remove", "Remove persistence entry");
cmd_persist_registry.addArgBool("--hklm", "Use HKEY_LOCAL_MACHINE (requires admin, default is HKCU)");
cmd_persist_registry.addArgString("name", true, "Registry value name");
cmd_persist_registry.addArgString("path", false, "Program path (required for --add)");

cmd_persist_registry.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = 0;  // 0 = add, 1 = remove
    let location = 0;  // 0 = HKCU, 1 = HKLM
    let valueName = parsed_json["name"];
    let programPath = parsed_json["path"] || "";
    
    if (parsed_json["--remove"]) {
        action = 1;
    } else if (!parsed_json["--add"]) {
        throw new Error("Use --add or --remove");
    }
    
    if (parsed_json["--hklm"]) {
        location = 1;
    }
    
    if (action == 0 && !programPath) {
        throw new Error("Program path is required for --add");
    }
    
    let bof_path = ax.script_dir() + "_bin/registry_run." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("int,int,cstr,cstr", [action, location, valueName, programPath]);
    let message = action == 0 ? `Task: Add registry persistence (${valueName})` : `Task: Remove registry persistence (${valueName})`;
    
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

// Scheduled Task Persistence
var cmd_persist_schtask = ax.create_command("schtask", "Add/Remove scheduled task persistence", "persist schtask --create MyTask C:\\path\\to\\app.exe --trigger ONLOGON");
cmd_persist_schtask.addArgBool("--create", "Create scheduled task");
cmd_persist_schtask.addArgBool("--delete", "Delete scheduled task");
cmd_persist_schtask.addArgFlagString("--trigger", "TRIGGER", false, "Trigger type: ONLOGON, DAILY, HOURLY (default: ONLOGON)");
cmd_persist_schtask.addArgString("name", true, "Task name");
cmd_persist_schtask.addArgString("path", false, "Program path (required for --create)");

cmd_persist_schtask.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = 0;  // 0 = create, 1 = delete
    let taskName = parsed_json["name"];
    let programPath = parsed_json["path"] || "";
    let trigger = parsed_json.hasOwnProperty("TRIGGER") ? parsed_json["TRIGGER"] : "ONLOGON";
    
    if (parsed_json["--delete"]) {
        action = 1;
    } else if (!parsed_json["--create"]) {
        throw new Error("Use --create or --delete");
    }
    
    if (action == 0 && !programPath) {
        throw new Error("Program path is required for --create");
    }
    
    let bof_path = ax.script_dir() + "_bin/schtask." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("int,cstr,cstr,cstr", [action, taskName, programPath, trigger]);
    let message = action == 0 ? `Task: Create scheduled task (${taskName})` : `Task: Delete scheduled task (${taskName})`;
    
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

// Service Persistence
var cmd_persist_service = ax.create_command("service", "Create/Delete/Start service persistence", "persist service --create MyService \"My Service\" C:\\path\\to\\app.exe");
cmd_persist_service.addArgBool("--create", "Create service");
cmd_persist_service.addArgBool("--delete", "Delete service");
cmd_persist_service.addArgBool("--start", "Start service");
cmd_persist_service.addArgBool("--auto", "Auto-start service on boot (use with --create)");
cmd_persist_service.addArgString("name", true, "Service name");
cmd_persist_service.addArgString("display", false, "Display name (required for --create)");
cmd_persist_service.addArgString("path", false, "Binary path (required for --create)");

cmd_persist_service.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = 0;  // 0 = create, 1 = delete, 2 = start
    let serviceName = parsed_json["name"];
    let displayName = parsed_json["display"] || "";
    let binaryPath = parsed_json["path"] || "";
    let startType = parsed_json["--auto"] ? 2 : 3;  // 2 = AUTO_START, 3 = DEMAND_START
    
    if (parsed_json["--delete"]) {
        action = 1;
    } else if (parsed_json["--start"]) {
        action = 2;
    } else if (!parsed_json["--create"]) {
        throw new Error("Use --create, --delete, or --start");
    }
    
    if (action == 0) {
        if (!displayName || !binaryPath) {
            throw new Error("Display name and binary path are required for --create");
        }
    }
    
    let bof_path = ax.script_dir() + "_bin/service_persist." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("int,cstr,cstr,cstr,int", [action, serviceName, displayName, binaryPath, startType]);
    
    let message = "";
    if (action == 0) message = `Task: Create service (${serviceName})`;
    else if (action == 1) message = `Task: Delete service (${serviceName})`;
    else message = `Task: Start service (${serviceName})`;
    
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

// Create main persist command with subcommands
var cmd_persist = ax.create_command("persist", "Windows persistence mechanisms");
cmd_persist.addSubCommands([cmd_persist_registry, cmd_persist_schtask, cmd_persist_service]);

// Register commands
var group_persist = ax.create_commands_group("Persistence-BOF", [cmd_persist]);
ax.register_commands_group(group_persist, ["beacon", "gopher"], ["windows"], []);

