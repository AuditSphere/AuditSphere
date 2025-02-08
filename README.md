# AuditSphere - File Server Auditing and Monitoring Software

🔒 Enhance the security and compliance of your Windows and Linux file servers with AuditSphere! 🔍

<img src="AuditSphere_Logo.png" alt="AuditSphere Logo" width="500">

## Introduction

AuditSphere is a powerful, open-source file server auditing and monitoring software designed to enhance security and compliance for both Windows and Linux systems. In an era where data breaches and unauthorized access are on the rise, AuditSphere provides real-time monitoring and auditing capabilities to help organizations stay ahead of potential threats.

### Project Background 🌐

AuditSphere was created to address the growing need for comprehensive file server auditing and monitoring solutions. It offers an integrated solution for Windows and Linux environments, ensuring consistent security measures.

### Project Aims & Objectives 🎯

**Project Aims:**
- Provide cross-platform integration to cover both Windows and Linux systems.
- Implement real-time monitoring and alerting for proactive threat detection.
- Ensure compliance with data protection regulations (e.g., GDPR, CCPA, etc.).
- Offer a user-friendly interface for easy setup and usage.
- Ensure scalability and performance to accommodate diverse environments.
- Enhance forensic analysis capabilities for incident response and investigation.

## Software 💻

AuditSphere consists of two main components:
- **Agents:** Install this on your file server.
- **Server:** A Django web application that stores logs and provides a user-friendly interface.

## Features 🚀

AuditSphere offers a range of powerful features, including:

- 📁 File Added
- 🗑️ File Removed
- 📝 File Modified
- 🔄 File Renamed
- 📦 File Moved
- 👤 Owner Changed
- 🔒 ACL (Access Control List) Changed
- ✔️ Successful Action Logging
- 🚧 Failed Action Logging (In Progress)

AuditSphere records the following information for each action:
- ⏰ Time of Action
- 👤 User Who Performed the Action
- 🌐 IP Address of User's Computer

### Supported Protocols 🌐

AuditSphere currently supports the following protocols:
- SMB (Server Message Block)

Please note that we are actively working on improving our feature set and expanding protocol support. 

## Reports 📊

This repository includes project reports covering various aspects of the project, including detailed requirement gathering, design, implementation, testing, and conclusions.

## Getting Started 🚀

### Installation

Learn how to install AuditSphere by following the instructions in the [Installation Guide](https://github.com/AuditSphere/AuditSphere/wiki).

### Usage

Get started with AuditSphere by referring to our [User Guide](https://github.com/AuditSphere/AuditSphere/wiki) for effective usage.

## Screenshots 📸
![Screenshot 2024-02-07 154402](https://github.com/AuditSphere/AuditSphere/assets/66524832/ce2d1f9a-e263-4732-9cf0-2443c117545d)
![Screenshot 2024-02-07 160856](https://github.com/AuditSphere/AuditSphere/assets/66524832/70121135-ae6d-4842-8104-ca6f92620195)
![Screenshot 2024-02-07 160953](https://github.com/AuditSphere/AuditSphere/assets/66524832/416a0275-cff6-48e2-9f21-62d15cb00a33)
![Screenshot 2024-02-07 161631](https://github.com/AuditSphere/AuditSphere/assets/66524832/b987415d-2076-42e7-ac0e-f4f2532f6f6b)


## Contributing 🤝

We welcome contributions from the community! Please read our [Contribution Guidelines](link_to_contributing.md) to get started.

## License 📜

This project is licensed under the [GNU General Public License 3](LICENSE.txt), making it open-source and accessible to all.
