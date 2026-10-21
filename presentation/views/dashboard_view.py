"""Dashboard view with system monitors, stats, and quick actions."""
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QGroupBox)
from PySide6.QtCharts import QChart, QChartView, QPieSeries
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QFont, QColor
from presentation.viewmodels.dashboard_viewmodel import DashboardViewModel
from presentation.widgets.system_monitor_widget import SystemMonitorWidget
from presentation.widgets.quick_actions_widget import QuickActionsWidget
from presentation.widgets.recent_analyses_widget import RecentAnalysesWidget


class DashboardView(QWidget):
    """Main dashboard page."""
    def __init__(self, viewmodel: DashboardViewModel):
        super().__init__()
        self._vm = viewmodel
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Welcome header
        title_label = QLabel(self.tr("Security Dashboard"))
        title_label.setObjectName("pageTitle")      # Orbitron neon title from the theme
        title_font = QFont("Orbitron", 18, QFont.Bold)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)

        # Top row: System monitor + Quick actions
        top_row = QHBoxLayout()
        self.system_monitor = SystemMonitorWidget()
        top_row.addWidget(self.system_monitor)

        self.quick_actions = QuickActionsWidget()
        top_row.addWidget(self.quick_actions)
        main_layout.addLayout(top_row)

        # Middle: severity of the stored analyses (filled from the repository by the view model)
        charts_group = QGroupBox(self.tr("Threat Statistics"))
        charts_layout = QVBoxLayout()
        self.chart_view = QChartView()
        chart = QChart()
        chart.setTitle(self.tr("Analyses by Severity"))
        self.severity_series = QPieSeries()
        chart.addSeries(self.severity_series)
        chart.setAnimationOptions(QChart.SeriesAnimations)
        self.chart_view.setChart(chart)
        self.chart_empty = QLabel(self.tr("No analyses yet — run a log, IOC or malware analysis to see statistics here."))
        self.chart_empty.setAlignment(Qt.AlignCenter)
        charts_layout.addWidget(self.chart_empty)
        charts_layout.addWidget(self.chart_view)
        self.chart_view.setVisible(False)
        charts_group.setLayout(charts_layout)
        main_layout.addWidget(charts_group)

        # Bottom: Recent analyses
        self.recent_analyses = RecentAnalysesWidget()
        main_layout.addWidget(self.recent_analyses)

    def _connect_signals(self):
        self._vm.gpu_metrics_updated.connect(self.system_monitor.update_metrics)
        self._vm.gpu_ollama_status.connect(self.system_monitor.update_provider)
        self._vm.recent_analyses_updated.connect(self.recent_analyses.update_analyses)
        self._vm.severity_counts_updated.connect(self.update_severity)
        self.quick_actions.action_triggered.connect(self._vm.run_quick_action)

    SEVERITY_COLORS = {"critical": "#dc2626", "high": "#f97316", "medium": "#eab308", "low": "#22c55e",
                       "info": "#64748b"}

    @Slot(dict)
    def update_severity(self, counts: dict):
        self.severity_series.clear()
        total = sum(counts.values())
        for level, value in counts.items():
            if value:
                slice_ = self.severity_series.append(f"{level.title()} ({value})", value)
                slice_.setColor(QColor(self.SEVERITY_COLORS.get(level, "#94a3b8")))
        self.chart_view.setVisible(total > 0)
        self.chart_empty.setVisible(total == 0)
