from distutils.core import setup
import datetime
import wx
import os,sys,inspect
import subprocess
import pefile
from hexdump import hexdump
import hashlib
import requests
class MyApp(wx.App):

    def OnInit(self):
        self.frame = MyFrame(None, title="EXE Analyser")
        self.SetTopWindow(self.frame)
        self.frame.Show()
        return True

class MyFrame(wx.Frame):
    def __init__(self, parent, id=wx.ID_ANY, title="",pos=wx.DefaultPosition, size=(500,500),style=wx.DEFAULT_FRAME_STYLE | wx.MINIMIZE_BOX | wx.MAXIMIZE_BOX | wx.CLOSE_BOX | wx.RESIZE_BORDER | wx.SYSTEM_MENU,name="MyFrame"):
        super(MyFrame, self).__init__(parent, id, title,pos, size, style, name)
        panel = wx.Panel(self,-1)
        open_button = wx.Button(self,label='Open', pos=(200,200))
        quit_button = wx.Button(self,label='Quit', pos=(200,230))
        report_button = wx.Button(self,label='Show report', pos=(200,260))
        self.panel = wx.Panel(self,pos=(0,0),size=(500,500))
        open_button.Bind(wx.EVT_BUTTON, self.OnOpen)
        quit_button.Bind(wx.EVT_BUTTON,self.OnQuit)
        report_button.Bind(wx.EVT_BUTTON, self.OnReport)
        path = os.path.abspath("D:\FYP\Tuts\HelloWorld\Resources\icons\exe.png")
        icon = wx.Icon(path, wx.BITMAP_TYPE_PNG)
        self.SetIcon(icon)


    def OnOpen(self, event):
        openFileDialog = wx.FileDialog(self, "Open .exe file", "", "", "All files (*.*)|*.*", wx.FD_OPEN)
        if openFileDialog.ShowModal() == wx.ID_OK:
            filename = openFileDialog.GetPath()
            self.progress()
            pef = pefile.PE(filename)
            l1 = open('C:\Users\Bhuvan\Desktop\Project\Logs\PE_Header_Sections.txt','w')
            sys.stdout = l1
            print pef
            l2 = open('C:\Users\Bhuvan\Desktop\Project\Logs\hexdump.txt','w')
            sys.stdout = l2
            hexdump(open(filename,'rb'))
            l = open(filename,'rb')
            b = l.read()
            l3 = open('C:\Users\Bhuvan\Desktop\Project\Logs\hash_value.txt','w') #hash_value
            l3.write(hashlib.md5(b).hexdigest())
            hash = hashlib.md5(b).hexdigest()
            params = {'apikey': '1a0aa958dee0e50c029b950d89e2bec20ec26bcda5676edf6123b88f2ae3e94b'}
            files = {'file': (filename, open(filename, 'r+'))}
            response_up = requests.post('http://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
            params = {'apikey': '1a0aa958dee0e50c029b950d89e2bec20ec26bcda5676edf6123b88f2ae3e94b','resource': hash}
            response_down = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            json_response = response_down.json()
            l4 = open('C:\Users\Bhuvan\Desktop\Project\Logs\VirusTotal_Report.txt','w')
            sys.stdout = l4
            print json_response
            if 'True' in open('C:\Users\Bhuvan\Desktop\Project\Logs\VirusTotal_Report.txt','r').read():
                print "\n\nTHE FILE IS A PACKER MALWARE"
            else:
                print "\n\nThis file needs to be analysed"


    def progress(self):
        progressMax = 8
        dialog = wx.ProgressDialog("Progress", "Time remaining", progressMax,style=wx.PD_AUTO_HIDE | wx.PD_ELAPSED_TIME | wx.PD_REMAINING_TIME | wx.PD_SMOOTH)
        keepGoing = True
        count = 0
        while keepGoing and count < progressMax:
            count = count + 1
            wx.Sleep(1)
            keepGoing = dialog.Update(count)
        dialog.Destroy()

    def OnQuit(self, event):
       if wx.MessageBox("Are you sure you want cancel scan?","Please confirm",wx.ICON_QUESTION | wx.YES_NO) != wx.NO:
            self.Close()
       else:
            self.Show()

    def OnReport(self,event):
        os.system("explorer C:\Users\Bhuvan\Desktop\Project\Logs")


if __name__ == "__main__":
    app = MyApp(False)
    app.MainLoop()
