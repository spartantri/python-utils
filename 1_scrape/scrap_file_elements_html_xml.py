#!/usr/bin/env python3
"""
Extract content of different types of tag from an html or xml file matching
regular expressions and save the output to a file.
There are other methods but this can be used to use more powerful regex.
"""
import re
source_file = 'source.html'
destination_file = 'output.html'

f = open(source_file, 'r')
content = f.read()
f.close()
rx = re.compile('<a href="(.*?)".*?(?:title="(.*?)").*?>(.*?)</a>|'
                '<li>(.*?)</li>') # for multiline add ', re.DOTALL)' after the regex

with open(destination_file, 'w') as quiz:
    quiz.write('<html><body>\n')
    for i in rx.findall(content):
        if i[0]:
            quiz.write("HREF  : " + i[0] + '\n')
        if i[1]:
            quiz.write("TITLE : " + i[1] + '\n')
        if i[2]:
            quiz.write("TEXT  : " + i[2] + '\n')
        if i[3]:
            quiz.write("ITEM  : " + i[3] + '\n')
    quiz.write('</body></html>')
