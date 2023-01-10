import PySimpleGUI as sg
import webbrowser

sg.theme('DarkAmber')

SYMBOL_UP =    '▲'
SYMBOL_DOWN =  '▼'

def collapse(layout, key):
    '''collapse helper function'''

    return sg.pin(sg.Column(layout, key=key))


def user_agent_fix(agent):
    '''helper function for parsing useragent
    replaces most characters with - so that the site can parse it
    '''
    fix = agent.lower()
    fix = fix.replace('/','-')
    fix = fix.replace('.','-')
    fix = fix.replace(';','-')
    fix = fix.replace(' ', '-')
    fix = fix.replace('(','-')
    fix = fix.replace(')','-')
    fix = fix.replace('_','-')
    fix = fix.replace(',','-')
    fix = fix.replace('--','-')

    return fix


section1 = [
    [sg.Button('VirusTotal', key='-VT-'), 
    sg.Button('AbuseIPDB', key='-AIPDB-'), 
    sg.Button('AlienVault', key='-AV-', tooltip='Requires url/domain not IP'),
    sg.Button('WhoIs', key='-WHOIS-'),
    sg.Button('TOR Relay', key='-TOR-', tooltip='Requires url/domain not IP'),
    sg.Button('URLScan', key='-URLSCAN-', tooltip='Requires url/domain not IP')
    ]
]

section2 = [
    [sg.Button('MAC Lookup', key='-MAC-'),
    sg.Button('UserAgent Lookup', key='-UA-'),
    sg.Button('File.net', key='-FILENET-', tooltip='Filename'),
    sg.Button('File Info', key='-FILEINFO-', tooltip='File extension'),
    sg.Button('EventID', key='-EVENTID-'),
    sg.Button('Decode Base64', key='-DECODE64-')
    ]
]

layout = [
    [sg.Text('OneStopSOC')],
    [sg.Text('Enter an IOA/IOC: '), sg.In(key='-INPUT-')],
    # SECTION1
    [sg.Text(SYMBOL_DOWN, enable_events=True, key='-OPENSEC1-'), sg.Text('IP/Domain/URL', enable_events=True, key='-OPENSEC1TEXT-')],
    [collapse(section1, '-SEC1-')],
    # SECTION2
    [sg.Text(SYMBOL_DOWN, enable_events=True, key='-OPENSEC2-'), sg.Text('Tools', enable_events=True, key='-OPENSEC2TEXT-')],
    [collapse(section2, '-SEC2-')],
]

window = sg.Window('OneStopSOC', layout)

opened1, opened2 = True, True

while True:
    event, values = window.read()

    input = values['-INPUT-']

    if event == sg.WIN_CLOSED:
        break

    if event.startswith('-OPENSEC1-'):
        opened1 = not opened1
        window['-OPENSEC1-'].update(SYMBOL_DOWN if opened1 else SYMBOL_UP)
        window['-SEC1-'].update(visible=opened1)

    if event.startswith('-OPENSEC2-'):
        opened2 = not opened2
        window['-OPENSEC2-'].update(SYMBOL_DOWN if opened2 else SYMBOL_UP)
        window['-SEC2-'].update(visible=opened2)

    if event == '-VT-':
        webbrowser.open(f'https://www.virustotal.com/gui/search/{input}', new=2)

    if event == '-AIPDB-':
        webbrowser.open(f'https://www.abuseipdb.com/check/{input}', new=2)

    if event == '-AV-':
        webbrowser.open(f'https://otx.alienvault.com/indicator/domain/{input}', new=2)

    if event == '-WHOIS-':
        webbrowser.open(f'https://www.whois.com/whois/{input}', new=2)

    if event == '-TOR-':
        webbrowser.open(f'https://metrics.torproject.org/rs.html#search/{input}', new=2)

    if event == '-URLSCAN-':
        webbrowser.open(f'https://urlscan.io/search/#{input}', new=2)

    if event == '-MAC-':
        webbrowser.open(f'https://maclookup.app/search/result?mac={input}', new=2)

    if event == '-UA-':
        fixedagent = user_agent_fix(input)

        webbrowser.open(f'https://user-agents.net/string/{fixedagent}', new=2)

    if event == '-FILENET-':
        webbrowser.open(f'https://www.file.net/search.html?q=site:file.net+{input}', new=2)

    if event == '-FILEINFO-':
        webbrowser.open(f'https://fileinfo.com/extension/{input}', new=2)

    if event == '-EVENTID-':
        webbrowser.open(f'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={input}', new=2)

    if event == '-DECODE64-':
        fixedinput = input.replace('==', '')

        webbrowser.open(f"https://cyberchef.org/#recipe=Magic(3,false,false,'')&input={fixedinput}", new=2)




window.close()