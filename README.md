# I/O Inventory Tool for macOS

Ця утиліта призначена для дослідження підсистеми введення-виведення macOS (Apple Silicon / Intel) з метою отримання MMIO-діапазонів, типів переривань, та класифікації пристроїв (PCIe / USB / SoC / I2C / Audio).

Результат виводиться у форматованій ASCII-таблиці, яка підходить для звітів з лабораторних робіт (аналог «Resources» у Windows Device Manager).

---

## 📌 Можливості

- Отримання списку I/O-компонентів прямо з IORegistry
- Виявлення PCIe-MMIO діапазонів через `assigned-addresses` / `reg`
- Додатковий парсинг `IODeviceMemory` (актуально для Apple Silicon)
- Визначення MSI/MSI-X (через IOInterruptSpecifiers)
- Класифікація пристроїв: PCIe / USB / I2C / SoC / Audio
- Вивід у табличному форматі, як у системній утиліті

---

## 🔧 Збірка

```bash
clang++ -std=c++17 io_inventory_pretty.cpp -o io_inv -framework IOKit -framework CoreFoundation
```