#!/bin/bash
compile_example() {
    project=$1
    echo "Compiling $project"

    project_name=$(basename "$project")
    
    # Use pushd to change to the project directory and save the current directory
    pushd "$project" > /dev/null
    
    # Run the compile command
    nargo compile --force --package ${project_name}
    
    # Use popd to return to the previous directory
    popd > /dev/null

}

# Loop over every child folder in the examples directory execpt target directory
for project in $(ls -d examples/*/ | grep -v target); do
    compile_example $project
done