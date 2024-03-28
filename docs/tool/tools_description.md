# tools description file

`bentoo` uses a TOML-based file to get information on how to run your SAST tools. The file format is as follows:

```TOML
# A single tool is defined as a pair (script, config)
# The script specifies the command to run
# The config specifies what keyword arguments to pass to the script
[[tools]]
script = "path to your runner script"
name = "script name"
# parse_command field is not needed if your tool produces output in the bentoo-sarif format
parse_command = { command = "your parsing command", args = "arguments to pass to your parsing command" }


[[tools.configs]]
name = "config name"
args = "arguments to pass to your script"

[[tools.configs]]
# you may specify multiple configs for a single script

[[tools]]
# and multiple scripts with their own configs
```

The paths to runner scripts are relational to the directory the tools description file is located in.
