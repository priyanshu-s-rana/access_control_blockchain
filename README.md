# AuthPrivacyChain

## A Blockchain-Based Access Control Framework with Privacy Protection in Cloud

**Empowering Secure Data Exchange**

### Overview
AuthPrivacyChain is a project that implements a blockchain-based access control framework designed to ensure privacy protection in cloud environments. It leverages blockchain technology for secure data exchange, access control mechanisms, and privacy preservation.

### Project Structure
- **`PrivacyChainApp`**: Main Django application folder containing the core functionality.
- **`contracts`**: Directory for smart contracts used in the blockchain implementation.
- **`truffle-config.js`**: Configuration file for Truffle, a development environment for Ethereum smart contracts.
- **`AuthPrivacyChain.json`**: Likely contains compiled contract data or metadata.
- **`.env`**: Environment configuration file for sensitive settings.
- **`manage.py`**: Django's command-line utility for administrative tasks.
- **`db.sqlite3`**: SQLite database file for development.
- **`migrations`**: Directory for database migration files.
- **`build`**: Directory for build artifacts.
- **`ipfs.exe`** and **`Start_IPFS.bat`**: Tools for interacting with IPFS (InterPlanetary File System), likely used for decentralized file storage.
- **`runServer.bat`**: Batch file to run the server.

### Features
- **User Authentication**: Login and signup functionality for different user roles.
- **Data Upload**: Allows data owners to upload data securely to the cloud.
- **Access Control**: Implements fine-grained access control using blockchain.
- **Data Sharing**: Secure data sharing mechanisms between data owners and users.
- **Revocation**: Ability to revoke access from users.
- **Indirect Access Control**: Additional layer of access control for enhanced security.
- **Graphical Representation**: Visualization of data access patterns or computation graphs.

### Technology Stack
- **Django**: Web framework for the application backend.
- **Ethereum Blockchain**: For decentralized access control using smart contracts.
- **Truffle**: Development and testing framework for Ethereum smart contracts.
- **IPFS**: Decentralized file storage system.
- **Solidity**: Programming language for writing smart contracts (version 0.8.11).

### Key Components

- Python 3.11+
- Node.js 16+
- npm or yarn
- IPFS Desktop or IPFS daemon
- Ganache (for local development)
- MetaMask (for blockchain interactions)

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/AuthPrivacyChain.git
   cd AuthPrivacyChain
   ```

2. **Set up Python environment**
   ```bash
   # Using pipenv (recommended)
   pip install pipenv
   pipenv install
   pipenv shell
   ```

3. **Install JavaScript dependencies**
   ```bash
   npm install -g truffle
   npm install -g ganache
   ```

4. **Set up environment variables**
   Create a `.env` file in the root directory:
   ```env
   DEBUG=True
   SECRET_KEY=your-secret-key-here
   DEPLOYED_CONTRACT_ADDRESS=your-contract-address
   BLOCKCHAIN_ADDRESS=http://127.0.0.1:8545
   CONTRACT_FILE=build/contracts/AuthPrivacyChain.json
   SALT=your-random-salt
   ```

5. **Start local blockchain**
   ```bash
   ganache-cli
   ```

6. **Deploy smart contracts**
   ```bash
   truffle migrate --network development --reset 
   ```

7. **Start IPFS**
   ```bash
   ipfs daemon
   # Or use the provided script
   ./Start_IPFS.bat  # Windows
   ```

8. **Run the development server**
   ```bash
   python manage.py runserver
   ```

## 📂 Project Structure

```
AuthPrivacyChain/
├── contracts/                  # Smart contracts (Solidity)
│   └── AuthPrivacyChain.sol    # Main smart contract
├── migrations/                 # Smart contract migrations
├── PrivacyChain/              # Django project settings
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── PrivacyChainApp/           # Main application
│   ├── static/                # Static files (CSS, JS, images)
│   │   ├── style.css
│   │   └── style_github.css   # Dark theme styles
│   ├── templates/             # HTML templates
│   │   ├── Login.html
│   │   ├── Signup.html
│   │   ├── UploadImage.html
│   │   └── ...
│   ├── utils/
│   │   └── SessionManager.py  # Session management
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── dynamic_accumulator.py # RSA Accumulator implementation
│   ├── models.py
│   ├── urls.py
│   └── views.py              # Request handlers
├── .env                      # Environment variables
├── manage.py                 # Django management script
├── Pipfile                   # Python dependencies
├── runServer.bat             # Windows server starter
├── Start_IPFS.bat            # IPFS starter script
└── truffle-config.js         # Truffle configuration
```

## 🔐 Security Features

- **RSA Accumulators**: For efficient credential management using dynamic accumulators that allow for membership testing without revealing individual members
- **IPFS Encryption**: Files are encrypted before storage
- **Smart Contract Access Control**: Granular permission system
- **Session Management**: Secure session handling
- **Input Validation**: Protection against common web vulnerabilities

## 🌐 API Endpoints

- `/login` - User authentication
- `/signup` - User registration
- `/upload` - File upload
- `/access` - Manage file access
- `/revoke` - Revoke access
- `/download` - Download files

## 📈 Performance

- Efficient RSA accumulator implementation
- Batch processing for bulk operations
- Asynchronous file handling
- Optimized blockchain interactions

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

For any questions or feedback, please contact:
- [Your Name] - [Your Email]
- Project Link: [https://github.com/yourusername/AuthPrivacyChain](https://github.com/yourusername/AuthPrivacyChain)

## 🙏 Acknowledgments

- [Ethereum](https://ethereum.org/)
- [IPFS](https://ipfs.io/)
- [Django](https://www.djangoproject.com/)
- [Truffle Suite](https://www.trufflesuite.com/)
