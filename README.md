PyVault is a command-line interface (CLI) tool designed for securely encrypting files using strong encryption methods. It’s perfect for protecting sensitive data, making it an essential tool for personal use.

## How to use

If you have a folder containing sensitive information that you'd like to encrypt with a password, follow these steps:

### Initialization

First, initialize the application in the target folder. Open a terminal in the folder and run:

```bash
vault init .
```

This will create a `config.json` file in the folder. Now you're ready to encrypt files.

> [!CAUTION]
> Do not delete the `config.json` file. It is required for decryption along with your password. Without it, decryption will be impossible.

### Commands

```bash
vault encrypt [OPTIONS]
vault decrypt [OPTIONS]
```

Each time you use these commands, the program will prompt you for your password. To skip the prompt, you can use the `-k` flag:

```bash
vault encrypt -k <your-password>
vault decrypt -k <your-password>
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
