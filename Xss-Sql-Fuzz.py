#!/usr/bin/env python        
#coding:utf-8
import sys
reload(sys)
sys.setdefaultencoding('utf-8') 

import os
import re
import urllib

from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
from burp import IContextMenuFactory
from javax.swing import JMenu
from javax.swing import JMenuItem
import hashlib
import urllib
import json


class BurpExtender(IBurpExtender, IHttpListener,IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Xss-Sql-Fuzz")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.issueAlert("Loaded Successfull.")

    def createMenuItems(self, invocation):
        self.menus = []
        self.mainMenu = JMenu("Xss-Sql-Fuzz")
        self.menus.append(self.mainMenu)
        self.invocation = invocation
        #print invocation.getSelectedMessages()[0].getRequest()
        menuItem = ['addXFF','addReferer','post fuzz1:x\'"><rivirtest>','post fuzz2:</script><img+src=0+onerror=alert(1)>','post fuzz3:\'-sleep(3)-\'','get fuzz1:x\'"><rivirtest>',
        'get fuzz2:</script><img+src=0+onerror=alert(1)>','get fuzz3:\'-sleep(3)-\'']
        for tool in menuItem:
            #self.mainMenu.add(JMenuItem(tool))
            if tool == 'addXFF':
                menu = JMenuItem(tool,None,actionPerformed=lambda x:self.modifyHeader(x))
                self.mainMenu.add(menu)
            elif tool == 'addReferer':
                menu = JMenuItem(tool,None,actionPerformed=lambda x:self.modifyHeader(x))
                self.mainMenu.add(menu)
            elif tool.startswith('post fuzz'):
                menu = JMenuItem(tool,None,actionPerformed=lambda x:self.postFuzz(x)) # 不能传入invocation,x传入的是当前munuItem的上下文
                self.mainMenu.add(menu)
            elif tool.startswith('get fuzz'):
                menu = JMenuItem(tool,None,actionPerformed=lambda x:self.getFuzz(x)) 
                self.mainMenu.add(menu)
    
    
        return self.menus if self.menus else None
        
    def modifyHeader(self,x):
        if x.getSource().text == 'addXFF': #通过获取当前点击的子菜单的 text 属性，确定当前需要执行的 command
            currentRequest = self.invocation.getSelectedMessages()[0]  #getSelectedMessages()返回数组，但有时为1个，有时2个
            requestInfo = self._helpers.analyzeRequest(currentRequest) # 该部分实际获取到的是全部的Http请求包
            self.headers = list(requestInfo.getHeaders())
            self.headers.append(u'X-Forwarded-For:127.0.0.1')
            self.headers.append(u'X-Client-IP:127.0.0.1')
            #print 'self.headers',self.headers
            bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():] # bytes[]类型
            self.body = self._helpers.bytesToString(bodyBytes) #bytes to string转换一下
            #print 'self.body:',self.body
            newMessage = self._helpers.buildHttpMessage(self.headers, self.body)
            currentRequest.setRequest(newMessage) #setRequest() 会动态更新setRequest\
        elif x.getSource().text == 'addReferer':
            currentRequest = self.invocation.getSelectedMessages()[0]  #getSelectedMessages()返回数组，但有时为1个，有时2个
            requestInfo = self._helpers.analyzeRequest(currentRequest) # 该部分实际获取到的是全部的Http请求包
            self.headers = list(requestInfo.getHeaders())
            print 'getUrl:',requestInfo.getUrl()
            self.headers.append('Referer: '+requestInfo.getUrl().toString())
            print self.headers
            bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():] # bytes[]类型
            self.body = self._helpers.bytesToString(bodyBytes) #bytes to string转换一下
            #print 'self.body:',self.body
            newMessage = self._helpers.buildHttpMessage(self.headers, self.body)
            currentRequest.setRequest(newMessage)
            

    def postFuzz(self,x):
        if x.getSource().text.startswith('post fuzz'):
            #print 'invocaton:',self.invocation.getSelectedMessages
            self.payload = x.getSource().text.split(':')[-1]
            currentRequest = self.invocation.getSelectedMessages()[0]
            requestInfo = self._helpers.analyzeRequest(currentRequest)
            self.headers = list(requestInfo.getHeaders())
            #print 'self.headers',self.headers
            bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
            self.body = self._helpers.bytesToString(bodyBytes)
            #print 'self.body:',self.body
            o,n = self.update_body(urllib.unquote(self.body))
            self.body = self.body.replace(o,n)
            newMessage = self._helpers.buildHttpMessage(self.headers, self.body)
            currentRequest.setRequest(newMessage)

    def getFuzz(self,x):
        if x.getSource().text.startswith('get fuzz'):
            self.payload = x.getSource().text.split(':')[-1]
            currentRequest = self.invocation.getSelectedMessages()[0] #return IHttpRequestResponse
            body = currentRequest.getRequest() #return byte[]
            requestInfo = self._helpers.analyzeRequest(currentRequest) #returns IResponseInfo
            paraList = requestInfo.getParameters() #array
           # print 'paraList',paraList
            new_requestInfo = body
            white_action = ['action','sign']
            for para in paraList:
                if para.getType() == 0 and not self.Filter(white_action,para.getName()):
                    value = para.getValue()+self.payload 
                    key = para.getName()
                    newPara = self._helpers.buildParameter(key, value, para.getType())
                    new_requestInfo = self._helpers.updateParameter(new_requestInfo,newPara) #updateParameter(byte[],IParameter) return byte[]
                    
            currentRequest.setRequest(new_requestInfo)

    def Filter(self,white_action,key):
        #return True if(key.lower() in white_action) else False #key in action # 完全匹配
        return True if([True for i in white_action if i in key.lower()]) else False  #action_item in key 模糊匹配，csrf_token,token_ctrf等都可以匹配到

    def update_body(self, body=""):
        try:
            o = body
            white_action = ['submit','token','code','id','password']
            #print 'body:',body
            for item in self.headers:
                if (item.startswith('Content-Type:') and 'application/json' in item) or body.startswith('{"'):
                    json_type = 1
                    break
                else:
                    json_type = 0
            #print 'json_type:',json_type
            if json_type == 0:
                params = o.split('&')
                for i in range(len(params)):
                    # querys = copy.deepcopy(params)
                    if self.Filter(white_action,params[i].split('=')[0]):
                        continue
                    params[i] = params[i] + self.payload
                n = '&'.join(params)
                #print 'n:',n
                return o,n
            if json_type == 1:
                print 'json type'
                data = json.loads(o)
                print 'data:',data
                for item in data:
                    if self.Filter(white_action,item):
                        continue
                    data[item] = data[item]+self.payload
                n = json.dumps(data)
                print 'n:',n
                return o,n
        except Exception,e:
            return e


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        # determine what tool we would like to pass though our extension:
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32: #if tool is Proxy Tab or repeater
            # determine if request or response:
            if not messageIsRequest:#only handle responses
                response = messageInfo.getResponse()
                 #get Response from IHttpRequestResponse instance
                analyzedResponse = self._helpers.analyzeResponse(response) # returns IResponseInfo
                headers = analyzedResponse.getHeaders()
                #替换iso8859-1
                # iterate though list of headers
                new_headers = []
                for header in headers:
                    # Look for Content-Type Header)
                    if header.startswith("Content-Type:"):
                        # Look for HTML response
                        # header.replace('iso-8859-1', 'utf-8')
                        # print header
                        new_headers.append(header.replace('iso-8859-1', 'utf-8'))
                    else:
                        new_headers.append(header)

                print new_headers

                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                #print body_string
                u_char_escape = re.search( r'(?:\\u[\d\w]{4})+', body_string)
                if u_char_escape:
                    # print u_char_escape.group()
                    u_char = u_char_escape.group().decode('unicode_escape').encode('utf8')
                    new_body_string = body_string.replace(u_char_escape.group(),'--'+u_char+'--')
                    new_body = self._helpers.bytesToString(new_body_string)
                    # print new_body_string
                    messageInfo.setResponse(self._helpers.buildHttpMessage(new_headers, new_body))