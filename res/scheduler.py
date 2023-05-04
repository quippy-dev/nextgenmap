import sys, os, platform, re
from .scheduler_dialog import Ui_SchedulerDialog
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QLineEdit
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QTextOption
from crontab import CronTab

script_name = os.path.basename(sys.modules['__main__'].__file__)
script_dir = os.path.dirname(sys.modules['__main__'].__file__)


class SchedulerDialog(QDialog, Ui_SchedulerDialog):
    def __init__(self, parent=None, main_window=None):
        super().__init__(parent)
        self.setupUi(self)
        self.main_window = main_window
        self.updating_cron_schedule = False
        self.toggling_custom_radio = False
        self.email_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.init_ui()
        self.install_cron_btn.pressed.connect(lambda: self.schedule_scan(preview=False))
        self.apply_alert_btn.pressed.connect(self.apply_alert_settings)
        self.apply_smtp_btn.pressed.connect(self.apply_smtp_settings)

    def init_ui(self):
        self.cboxes = [self.min_cbox, self.hour_cbox, self.date_cbox, self.month_cbox, self.day_cbox]
        cbox_labels = [["Minute"] + [str(i) for i in range(0, 60)],
                       ["Hour"] + [str(i) for i in range(0, 24)],
                       ["Date"] + [str(i) for i in range(1, 32)],
                       ["Month"] + ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Nov", "Dec"],
                       ["Day"] + ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]]

        for cbox, labels in zip(self.cboxes, cbox_labels):
            model = QStandardItemModel()
            for label in labels:
                item = QStandardItem(label)
                item.setToolTip(f"Extended description for {label}")
                model.appendRow(item)
            cbox.setModel(model)
            cbox.setCurrentIndex(0)

        self.cron_schedule.document().setDefaultTextOption(QTextOption(Qt.AlignmentFlag.AlignCenter))
        for radio in [self.hourly_radio, self.daily_radio, self.weekly_radio, self.custom_radio]:
            radio.toggled.connect(self.update_cron_schedule)
        for cbox in self.cboxes:
            cbox.currentIndexChanged.connect(self.update_cron_schedule)
        self.cron_schedule.textChanged.connect(self.parse_cron_schedule)
        self.email_receiver.textChanged.connect(self.update_cron_schedule)
        self.html_checkbox.toggled.connect(self.schedule_scan)
        self.xml_output.textChanged.connect(self.schedule_scan)
        self.sender_has_focus = False
        self.update_cron_schedule()
        self.schedule_scan()

        # check if machine is on Windows or Linux:
        if platform.system() == "Windows":
            self.install_cron_btn.setText("No Cron on Windows!")
            self.install_cron_btn.setEnabled(False)

    def apply_alert_settings(self):
        self.apply_alert_btn.setEnabled(False)
        self.apply_alert_btn.setText("Applied")

    def apply_smtp_settings(self):
        self.apply_smtp_btn.setEnabled(False)
        self.apply_smtp_btn.setText("Applied")

    def update_cbox_states(self, cron_text, cb_states, cb_indices):
        for i, part in enumerate(cron_text.split()):
            cb_states[i] = not any(c in part for c in ',/-')
            cb_indices[i] = int(part) + 1 if part.isdigit() else 0

    def schedule_scan(self, preview=True):
        python_path = sys.executable
        command_entry = self.main_window.command_entry.text()
        output_filename = self.xml_output.text()
        html_flag = ""
        name, extension = os.path.splitext(output_filename)
        if self.html_checkbox.isChecked():
            html_flag = "--html"
            output_filename = name + '.html'
        else: output_filename = name + '.xml'

        self.xml_output.setText(output_filename)
        output_path = os.path.join(script_dir, output_filename)
        script_path = os.path.join(script_dir, script_name)

        if preview:
            cmd_preview = f'python3 {script_name} --scan --command "{command_entry}" --output {output_filename} {html_flag}'
            self.cron_preview.setText(cmd_preview)
            return

        command = f'{python_path} {script_path} --scan --command "{command_entry}" --output {output_path} {html_flag}'
        cron_time = self.cron_schedule.toPlainText()
        self.user_cron = CronTab(user=True)
        self.job = self.user_cron.new(command, comment='NextgeNmap scheduled scan')
        self.job.setall(cron_time)
        self.install_cron_btn.setEnabled(False)
        self.install_cron_btn.setText("Installed")
        try:
            self.user_cron.write()
        except IOError as e:
            print(e)
            return

    def parse_cron_schedule(self):
        guru_format = f"https://crontab.guru/#{self.cron_schedule.toPlainText().replace(' ', '_')}"
        self.guru_link.setText(f'<a href="{guru_format}"><span style="text-decoration:none;color:#007BFF;">{guru_format}</span></a>')

        if self.updating_cron_schedule:
            return

        cron_text = self.cron_schedule.toPlainText().strip()
        cron_pattern = re.compile(r'^(\*|\d+|\d+-\d+|\*/\d+|\d+(,\d+)*)( (\*|\d+|\d+-\d+|\*/\d+|\d+(,\d+)*)){4}$')
        if not cron_pattern.match(cron_text):
            return

        self.sender_has_focus = self.sender() and self.sender().hasFocus()
        if self.sender_has_focus:
            self.custom_radio.setChecked(True)

        cb_states = [True] * 5
        cb_indices = [0] * 5
        self.update_cbox_states(cron_text, cb_states, cb_indices)

        for cb, state, index in zip(self.cboxes, cb_states, cb_indices):
            cb.setEnabled(state)
            cb.setCurrentIndex(index)
        self.sender_has_focus = False

    def update_cron_schedule(self):
        self.schedule_scan()
        if self.sender() == self.cron_schedule or self.sender_has_focus:
            return

        self.updating_cron_schedule = True
        is_custom = self.custom_radio.isChecked()

        # Set the enabled state of the ComboBoxes based on the checked radio button
        cbox_states = {
            self.min_cbox: self.hourly_radio.isChecked() or self.daily_radio.isChecked() or self.weekly_radio.isChecked() or is_custom,
            self.hour_cbox: self.daily_radio.isChecked() or self.weekly_radio.isChecked() or is_custom,
            self.date_cbox: is_custom,
            self.month_cbox: is_custom,
            self.day_cbox: self.weekly_radio.isChecked() or is_custom,
        }

        for cbox, state in cbox_states.items():
            cbox.setEnabled(state)
            if not state:
                cbox.setCurrentIndex(0)

        minute = self.min_cbox.currentText() if self.min_cbox.currentText() != "Minute" else "*"
        hour = self.hour_cbox.currentText() if self.hour_cbox.currentText() != "Hour" else "*"
        date = self.date_cbox.currentText() if is_custom and self.date_cbox.currentText() != "Date" else "*"
        month = str(self.month_cbox.currentIndex()) if is_custom and self.month_cbox.currentText() != "Month" else "*"
        day = str(self.day_cbox.currentIndex() - 1) if (is_custom or self.weekly_radio.isChecked()) and self.day_cbox.currentText() != "Day" else "*"

        if self.hourly_radio.isChecked():
            minute = "0" if minute == "*" else minute
            self.cron_schedule.setPlainText(f"{minute} * * * *")
        elif self.daily_radio.isChecked():
            minute = "0" if minute == "*" else minute
            hour = "0" if hour == "*" else hour
            self.cron_schedule.setPlainText(f"{minute} {hour} * * *")
        elif self.weekly_radio.isChecked():
            minute = "0" if minute == "*" else minute
            hour = "0" if hour == "*" else hour
            day = "0" if day == "*" else day
            self.cron_schedule.setPlainText(f"{minute} {hour} * * {day}")
        else:
            cron_expression = f"{minute} {hour} {date} {month} {day}"
            self.cron_schedule.setPlainText(cron_expression)

        self.updating_cron_schedule = False
