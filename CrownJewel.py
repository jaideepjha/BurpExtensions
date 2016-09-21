from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
from javax.swing import *
import java.io
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    def __init__(self):
    	self._callbacks = ''
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("CrownJewelFinder")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        self.configSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        label1 = JLabel("Burp State File")
        panel1 = JPanel()
        panel1.add(label1)
        self.textfield1 = JTextField('Provide Burp State File Path... ',15)
        panel1.add(self.textfield1)
        self.loadFileButton = JButton('Load File',actionPerformed=self.LoadFile)
        panel1.add(self.loadFileButton)
        self.configSplitPane.setLeftComponent(panel1);
        
        
        
        # customize our UI components
        callbacks.customizeUiComponent(self.configSplitPane)
        callbacks.customizeUiComponent(panel1)
        
        
        #Compile RegEx Patterns
        regex = "[A-Z0-9]{5,20}"
    	self.myre = re.compile(regex, re.DOTALL)
        
        # restore burp state
        self.file = ''
        #file = java.io.File('E:/Projects/CPF/Burp-States-Dump/Iteration3-1June2015/172.24.101.42/2015.06.01_08.17.burp')
        #print file.__class__
        #print file.exists()
        #callbacks.restoreState(file)
        
        #get Request/Response from history
        #reqres = callbacks.getProxyHistory()
        #print len(reqres)
        #self.RetrievInterestingRequests(callbacks, reqres)        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
	self.doInterestingThings()
	#self.fileInput()
        return

    def doInterestingThings(self):
        file = java.io.File('E:/Projects/CPF/Burp-States-Dump/Iteration3-1June2015/172.24.101.42/2015.06.01_08.17.burp')
        #print file.__class__
        #print file.exists()
        self._callbacks.restoreState(file)
        
        #get Request/Response from history
        reqres = self._callbacks.getProxyHistory()
        print len(reqres)
        #self.RetrievInterestingRequests(self._callbacks, reqres)
    
    def fileInput(self):
    	frame = JFrame("Enter File Path")
        frame.setSize(600, 200)
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE)
        pnl = JPanel()
        frame.add(pnl)
        self.textfield1 = JTextField('Provide Burp State File Path... ',15)
        pnl.add(self.textfield1)
        #self.textfield2 = JTextField('and click Copy', 15)
        #pnl.add(self.textfield2)
        copyButton = JButton('Load File',actionPerformed=self.LoadFile)
        pnl.add(copyButton)
        frame.pack()
        frame.setVisible(True)
        return
        
    def LoadFile(self, event):        
	self.doInterestingThings()        
	
    def getTabCaption(self):
        return "Tamperable Parameters"
        
        
    #
    # implement ITab
    #
    
    def RetrievInterestingRequests(self, callbacks, reqres):
    	f = open('temp.txt','w')
    	for index, r in enumerate(reqres):
    	    url = callbacks.getHelpers().analyzeRequest(r.getHttpService(), r.getRequest()).getUrl()
    	    #if callbacks.isInScope(url):
    	    if True:
    	        params = callbacks.getHelpers().analyzeRequest(r.getHttpService(), r.getRequest()).getParameters()
    	        for param in params:
    	          paramName = callbacks.getHelpers().urlDecode(param.getName())
    	          paramVal =  callbacks.getHelpers().urlDecode(param.getValue())
    	          if (('cpfaccount' in paramName.lower()) or ('transactionnumber' in paramName.lower()) or ('nric' in paramName.lower())):    	          
    	              #regex = "[A-Z0-9]+{5,20}"
    	              #myre = re.compile(regex, re.DOTALL)
    	              match_vals = self.myre.findall(paramVal)
    	              if match_vals > 0:
    	                  print str(url) + str(index+1)
    	                  f.write(str(url) +' : '+ str(index+1))
    	                  f.write("\n")
    	                  self._lock.acquire()
			  row = self._log.size()
			  self._log.add(LogEntry(4, callbacks.saveBuffersToTempFiles(r), callbacks.getHelpers().analyzeRequest(r.getHttpService(), r.getRequest()).getUrl()))
			  self.fireTableRowsInserted(row, row)
            		  self._lock.release()
        f.close()
        return
    
    def getUiComponent(self):
        return self._splitpane        
        

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""


    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()
        

#
# extend JTable to handle cell selection
#
    
class Table(JTable):

    def LoadFile(self,event):
        #self.textfield2.text = self.textfield1.text
        #E:\Projects\CPF\Burp-States-Shared\Test controller 47\6th Jul\vm 51\2015.07.06_11.36.burp
        #file = java.io.File('E:/Projects/CPF/Burp-States-Dump/Iteration3-1June2015/172.24.101.42/2015.06.01_08.17.burp')
        #print self.textfield1
        #file = java.io.File(self.textfield1.text)
        #self._extender._callbacks.restoreState(file)
        #reqres = self._extender._callbacks.getProxyHistory()
        #self._extender.RetrievInterestingRequests(self._extender._callbacks, reqres)
        self._extender.doInterestingThings()
        print self.textfield1.text
        return
        #self._extender.doInterestingThings()
    
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        
    
    	#frame = JFrame("Jython JText Field Example")
        #frame.setSize(200, 150)
        #frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE)
        #pnl = JPanel()
        #frame.add(pnl)
        #self.textfield1 = JTextField('Provide Burp State File Path... ',15)
        #pnl.add(self.textfield1)
        #self.textfield2 = JTextField('and click Copy', 15)
        #pnl.add(self.textfield2)
        #copyButton = JButton('Load File',actionPerformed=self.LoadFile)
        #pnl.add(copyButton)
        #frame.pack()
        #frame.setVisible(True)
        #return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return
    
#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        return
              