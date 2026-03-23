Web Application Security Explorer and Scanner
Project Overview
A Rust-based Command Line Interface (CLI) tool designed for educational purposes to demonstrate web application security vulnerabilities, focusing on URL manipulation, directory traversal, and database interaction. The tool assumes authorized access to the target web application.

Core Features
1. Port Scanning: Scan for open ports on a target IP address
2. Web App Enumeration: Enumerate directories, files, and potential vulnerabilities via URL manipulation
3. Database Interaction: Interact with the web application's database (read data, modify queries)
4. File Manipulation: Explore and modify files on the web server (demonstrating potential vulnerabilities)
5. Authorization Bypass: Demonstrate techniques to bypass authorization checks
6. Educational Output: Provide clear output to demonstrate vulnerabilities and risks

Implementation Details
- Use Rust as the primary programming language
- Utilize reqwest crate for HTTP requests
- Use std::net for port scanning
- Parse URLs and manipulate paths using url and path crates
- Implement database interaction using SQL queries (e.g., MySQL, PostgreSQL)

Example Use Cases
1. Scanning a target web application: scanner me.example.com
2. Exploring files and directories: scanner me.example.com /admin
3. Interacting with database: scanner me.example.com db:SELECT * FROM users

Project Structure
- src/main.rs: Main entry point and CLI argument parsing
- src/scanner.rs: Web app scanning and enumeration logic
- src/database.rs: Database interaction logic
- src/file.rs: File manipulation logic
- Cargo.toml: Project dependencies and configuration

Educational Goals
- Demonstrate common web application vulnerabilities (LFI, RFI, SQLi)
- Teach secure coding practices and vulnerability mitigation
- Show impact of misconfigurations and insecure coding

Constraints
- No brute-force attacks or unauthorized access
- Focus on educational demonstration, not exploitation
- Assume authorized access to the target web application

Rust Dependencies
- reqwest: HTTP requests
- url: URL parsing and manipulation
- std::net: Port scanning
- sqlx: Database interaction (optional)

This blueprint provides a comprehensive outline for creating a web application security scanner and explorer in Rust, focusing on educational purposes and authorized access.
it should also check for ratelimiting 