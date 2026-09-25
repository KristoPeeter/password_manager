# SV

## Project Scope
SV is a local, command-line password manager built in Rust. The primary goal of this tool is to securely store and retrieve credentials while prioritizing memory safety, secure authentication, and encrypted local storage.

Designed to run entirely offline, focusing on protecting data at rest and minimizing the time sensitive information exists in memory.

## Planned Interface
To prevent passwords from being leaked into terminal history files, the application will use an interactive terminal interface rather than accepting passwords via standard command-line arguments.

The planned screens and flows are:

1. **Authentication Screen:** 
   - Prompts the user to log in or create a new vault.
   - Securely masks password inputs.
2. **Main Menu:** 
   - An interactive menu to navigate the application.
3. **Action Screens:**
   - **Add Credential:** Prompts for service details and a password.
   - **View Vault:** Displays saved credentials and explicitly clears the screen when finished.
   - **Exit:** Safely closes the application.

## How to Build and Run

### Prerequisites
You must have the Rust toolchain installed on your system.

### Building the Project


```bash
cargo build
```
### Running the Project


```bash
cargo run
```