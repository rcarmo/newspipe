#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# $NoKeywords: $   for Visual Sourcesafe, stop replacing tags
__revision__ = "$Revision: 1.5 $"
__revision_number__ = __revision__.split()[1]
__url__ = "https://newspipe.sourceforge.net"
__author__ = "Ricardo M. Reyes <reyesric@ufasta.edu.ar>"
__maintainer__ = "Rui Carmo"

from pprint import pprint
import xml.dom.minidom
from htmlentitydefs import  *
from datetime import datetime

def getText(nodelist):
    rc = ""
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc = rc + node.data
    return rc

def to_dict(root):
    result = {}

    if root.getElementsByTagName ('outline'):
        outline = True
    else:
        outline = False

    for attr, value in root.attributes.items():
        result[attr] = value

    if outline:
        result[u'childs'] = {}
        for child in [x for x in root.childNodes if x.nodeName == 'outline']:
            attribute = child.attributes.get('title', child.attributes.get('text', None))
            if attribute:
                name = attribute.value
            else:
                name = ''
                
            if name in result[u'childs'].keys():
                i = 1
                original = name
                name = original + str(i)
                while name in result[u'childs'].keys():
                    i += 1
                    name = original + str(i)
                # end while
    
            result[u'childs'][name] = to_dict(child)

    else:
        for node in root.childNodes:
            result[node.nodeName] = getText(node.childNodes)


    return result
   

def ParseOPML(data):

    result = {}

    dom = xml.dom.minidom.parse(data)

    node = dom.getElementsByTagName('opml')[0]
    result[u'opml'] = {u'head':to_dict(node.getElementsByTagName('head')[0]), 
                       u'body':to_dict(node.getElementsByTagName('body')[0])}

    #result = to_dict(dom)

    dom.unlink()

    return result
   

def handle_branch(rama, resultados, antecesores, valores_heredados):
    valores = {}
    for key in rama.keys():
        if key != 'childs':
            valores[key] = rama[key]
        

    for attr, value in valores_heredados.items():
        if not attr in valores.keys():
            valores[attr] = value


    if 'childs' in rama.keys():
        children = rama['childs']
        for child in children.keys():
            handle_branch (children[child], resultados, antecesores + [child,], valores)

    else:
        if antecesores.__len__() > 1:
            valores[u'path'] = '/' + u'/'.join(antecesores[:-1])
        else:
            valores[u'path'] = '/'

        resultados += [valores,]
   

def ListToDict(items):
    result = {}

    for attr, value in items:
        result[attr] = value.strip()

    return result
   

def flatten_tree(tree, defaults=None):
    items = []

    handle_branch(tree['opml']['body'], items, [], {})

    result = {'head':ListToDict(tree['opml']['head'].items()),
              'body':items}
            
    # add an index value to each item            
    for i, each in enumerate(items):
        each[u'index'] = unicode(str(i))
                  
    # add the default values to those item that are not complete
    if defaults:
        for each in items:
            for key,value in defaults.items():
                if not isinstance(key, unicode):
                    key = unicode(key)
                if not isinstance(value, unicode):
                    value = unicode(value)
                if not key in each.keys():
                    each[key] = value

    return result
 

entities = {}
for key,value in entitydefs.items():
    entities[unicode(value, 'latin1')] = unicode(key)
# end for

def escape (text):
    aux = []
    for each in text:
        if each in entities.keys():
            aux.append ('&'+entities[each]+';')
        else:
            aux.append (each)
    return ''.join(aux)

def generarOPML (feedList):
    doc = xml.dom.minidom.Document()
    
    opml = doc.createElement ('opml')
    opml.setAttribute ('version', '1.1')
    doc.appendChild(opml)
    
    head = doc.createElement ('head')
    opml.appendChild(head)
    
    for each, value in feedList['head'].items():
        if value.strip():
            if each != 'dateModified':
                attr = doc.createElement (each)
                ptext = doc.createTextNode (value)
                attr.appendChild (ptext)
                head.appendChild (attr)

    attr = doc.createElement ('dateModified')
    ptext = doc.createTextNode (str(datetime.now()))
    attr.appendChild (ptext)
    head.appendChild (attr)
    

    body = doc.createElement('body')
    opml.appendChild(body)
    for each in feedList['body']:
        outline = doc.createElement ('outline')
        for key, value in each.items():
            outline.setAttribute (key, value)
        body.appendChild (outline)

    return doc.toprettyxml(encoding='utf-8')

if __name__ == '__main__':
    pprint (flatten_tree(ParseOPML('test.opml')))
