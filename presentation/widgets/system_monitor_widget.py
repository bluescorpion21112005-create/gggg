from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar
from PySide6.QtCore import Slot
from core.gpu_monitor import GPUMetrics

class SystemMonitorWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        title = QLabel(self.tr("System Resources"))
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        # CPU
        self.cpu_label = QLabel(self.tr("CPU: 0%"))
        layout.addWidget(self.cpu_label)

        # RAM
        self.ram_label = QLabel(self.tr("RAM: 0%"))
        layout.addWidget(self.ram_label)

        # GPU
        self.gpu_label = QLabel(self.tr("GPU: N/A"))
        layout.addWidget(self.gpu_label)
        self.gpu_util_bar = QProgressBar()
        self.gpu_util_bar.setRange(0, 100)
        layout.addWidget(QLabel(self.tr("GPU Utilization:")))
        layout.addWidget(self.gpu_util_bar)

        self.gpu_mem_bar = QProgressBar()
        self.gpu_mem_bar.setRange(0, 100)
        layout.addWidget(QLabel(self.tr("GPU Memory:")))
        layout.addWidget(self.gpu_mem_bar)

        self.gpu_temp_label = QLabel(self.tr("Temp: N/A"))
        layout.addWidget(self.gpu_temp_label)

        self.gpu_model_label = QLabel("")
        self.gpu_model_label.setWordWrap(True)
        layout.addWidget(self.gpu_model_label)

    @Slot(dict)
    def update_provider(self, status: dict):
        """Local LLM (Ollama) models in memory and how much of each runs on the GPU."""
        loaded = status.get("loaded") or []
        if status.get("provider") != "ollama" or not loaded:
            self.gpu_model_label.setText("")
            return
        parts = [f"{m['name']} — {m['gpu_percent']}% GPU" if m["gpu_percent"] else f"{m['name']} — CPU"
                 for m in loaded]
        self.gpu_model_label.setText(self.tr("Ollama: %1").replace("%1", ", ".join(parts)))

    @Slot(GPUMetrics)
    def update_metrics(self, metrics: GPUMetrics):
        self.cpu_label.setText(f"CPU: {metrics.cpu_usage:.1f}%")
        self.ram_label.setText(f"RAM: {metrics.ram_usage:.1f}%")
        if metrics.rocm_available:
            self.gpu_label.setText(f"GPU: {metrics.gpu_name}" + (f" ({metrics.gfx})" if metrics.gfx else ""))
            self.gpu_util_bar.setValue(int(metrics.gpu_utilization))
            mem_percent = (metrics.memory_used / metrics.memory_total * 100) if metrics.memory_total > 0 else 0
            self.gpu_mem_bar.setValue(int(mem_percent))
            self.gpu_temp_label.setText(f"Temp: {metrics.temperature:.1f}°C")
        else:
            self.gpu_label.setText(self.tr("GPU: CPU only"))
            self.gpu_util_bar.setValue(0)
            self.gpu_mem_bar.setValue(0)
            self.gpu_temp_label.setText(self.tr("Temp: N/A"))