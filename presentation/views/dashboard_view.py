"""Dashboard view with system monitors, stats, and quick actions."""
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QGroupBox, QGridLayout, QPushButton, QScrollArea)
from PySide6.QtCharts import QChart, QChartView, QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis
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
        title_label = QLabel("Security Dashboard")
        title_font = QFont("Segoe UI", 18, QFont.Bold)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)

        # Top row: System monitor + Quick actions
        top_row = QHBoxLayout()
        self.system_monitor = SystemMonitorWidget()
        top_row.addWidget(self.system_monitor)

        self.quick_actions = QuickActionsWidget()
        top_row.addWidget(self.quick_actions)
        main_layout.addLayout(top_row)

        # Middle: Statistics charts (placeholder)
        charts_group = QGroupBox("Threat Statistics")
        charts_layout = QVBoxLayout()
        self.chart_view = QChartView()
        # Create a simple pie chart as placeholder
        chart = QChart()
        chart.setTitle("Alerts by Severity")
        series = QPieSeries()
        series.append("Critical", 2)
        series.append("High", 5)
        series.append("Medium", 10)
        series.append("Low", 15)
        chart.addSeries(series)
        chart.setAnimationOptions(QChart.SeriesAnimations)
        self.chart_view.setChart(chart)
        charts_layout.addWidget(self.chart_view)
        charts_group.setLayout(charts_layout)
        main_layout.addWidget(charts_group)

        # Bottom: Recent analyses
        self.recent_analyses = RecentAnalysesWidget()
        main_layout.addWidget(self.recent_analyses)

    def _connect_signals(self):
        self._vm.gpu_metrics_updated.connect(self.system_monitor.update_metrics)
        self._vm.recent_analyses_updated.connect(self.recent_analyses.update_analyses)
        self.quick_actions.action_triggered.connect(self._vm.run_quick_action)