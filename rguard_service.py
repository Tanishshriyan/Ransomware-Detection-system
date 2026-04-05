import win32serviceutil
import win32service
import win32event
import servicemanager
import subprocess
import sys
import os

class RansomGuardService(win32serviceutil.ServiceFramework):

    _svc_name_ = "RansomGuardService"
    _svc_display_name_ = "RansomGuard Ransomware Detection System"
    _svc_description_ = "Real-time AI-powered ransomware detection using behavioral fingerprinting."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.process = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        if self.process:
            self.process.terminate()

        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):

        servicemanager.LogInfoMsg("RansomGuard Service Starting")

        project_dir = os.path.dirname(os.path.abspath(__file__))
        run_file = os.path.join(project_dir, "run.py")

        self.process = subprocess.Popen(
            [sys.executable, run_file],
            cwd=project_dir
        )

        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(RansomGuardService)