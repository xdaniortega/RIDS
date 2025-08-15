# RIDS - Runtime Intrusion Detection System

## 📖 Technical Documentation

<div align="center">
  <h3>🔬 Project Whitepaper</h3>
  <object 
    data="RIDS-whitepaper.pdf" 
    width="90%" 
    height="700" 
    type="application/pdf"
    style="border: 2px solid #e1e4e8; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
  </object>
</div>

## 🎯 Project Description

RIDS (Runtime Intrusion Detection System) is an advanced runtime intrusion detection system that uses virtualization techniques to monitor and protect systems in real-time. The project is based on the Bareflank framework to implement a custom hypervisor that provides an additional security layer.

## ✨ Key Features

- **🛡️ Real-Time Detection**: Continuous system monitoring during execution
- **🔧 Custom Hypervisor**: Based on Bareflank for maximum flexibility
- **📊 Performance Analysis**: Detailed metrics of system impact
- **🏗️ Modular Architecture**: Extensible and maintainable design
- **🔍 Granular Monitoring**: System-level event capture

## 🏗️ System Architecture

### Main Components

```
RIDS/
├── hypervisor/           # Custom hypervisor code
│   ├── bfack/           # Recognition component
│   ├── bfdriver/        # System driver
│   ├── bfvmm/           # Hypervisor virtual machine
│   └── bfsdk/           # Development kit
├── Analisis/             # Performance analysis and metrics
│   ├── perf/            # Performance data
│   └── cpuTest/         # CPU tests
└── RIDS-whitepaper.pdf  # Complete technical documentation
```

### Technologies Used

- **Bareflank**: Open-source hypervisor framework
- **C++**: Primary language for hypervisor development
- **Assembly**: Low-level optimizations for x64 and ARM64
- **CMake**: Cross-platform build system

## 📊 Performance Analysis

The project includes detailed analysis of system performance impact:

- **CPU Metrics**: Analysis before, during, and after implementation
- **Performance Charts**: System behavior visualizations
- **Comparisons**: Impact evaluation in different configurations

## 🚀 Installation and Usage

### Prerequisites

- Compatible operating system (Linux, Windows, EFI)
- C++17 compatible compiler
- CMake 3.15 or higher
- Hardware with virtualization support

### Compilation

```bash
# Clone the repository
git clone https://github.com/xdaniortega/RIDS.git
cd RIDS

# Configure and compile
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## 📚 Documentation

- **📄 [Complete Whitepaper](RIDS-whitepaper.pdf)**: Detailed technical analysis of the project
- **🔬 [Performance Analysis](Analisis/)**: Performance metrics and charts
- **💻 [Source Code](hypervisor/)**: Hypervisor implementation

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## 👥 Authors

- **Daniel Ortega** - *Initial development* - [RIDS](https://github.com/xdaniortega/RIDS)

## 🙏 Acknowledgments

- **Bareflank Team** for the hypervisor framework
- **Security community** for feedback and testing
- **Contributors** who have helped improve the project

---

<div align="center">
  <p><strong>⭐ If this project is useful to you, consider giving it a star on GitHub</strong></p>
  <p>For more technical information, check our <a href="RIDS-whitepaper.pdf">complete whitepaper</a></p>
</div>
