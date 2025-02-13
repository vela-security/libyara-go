rule Backdoor_WebShell_asp2 : ASPXSpy2
{
    meta:
    description= "Detect ASPXSpy"
    author = "xylitol@temari.fr"
    date = "2019-02-26"
    // May only the challenge guide you
    strings:
    $string1 = "CmdShell" wide ascii
    $string2 = "ADSViewer" wide ascii
    $string3 = "ASPXSpy.Bin" wide ascii
    $plugin = "Test.AspxSpyPlugins"
 
    condition:
    3 of ($string*) or $plugin
}