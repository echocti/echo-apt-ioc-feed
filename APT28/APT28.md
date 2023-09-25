# IoC


|IoC|Type|Description|
|---|---|---|
|650f0d694c0928d88aeeed649cf629fc8a7bec604563bca716b1688227e0cc7e|SHA256|Azov|
|100c5e4d5b7e468f1f16b22c05b2ff1cfaa02eafa07447c7d83e2983e42647f0|SHA256|Somnia_07_08_22_with_FunnySomnia.rar|
|ac5e68c15f5094cc6efb8d25e1b2eb13d1b38b104f31e1c76ce472537d715e08|SHA256|Somnia_07_08_22_with_FunnySomnia.exe (Somnia)|
|99cf5c03dac82c1f4de25309a8a99dcabf964660301308a606cdb40c79d15317|SHA256|1.exe (Cobalt Strike Beacon)|
|156965227cbeeb0e387cb83adb93ccb3225f598136a43f7f60974591c12fafcf|SHA256|funnysomnia.exe|
|e449c28e658bafb7e32c89b07ddee36cadeddfc77f17dd1be801b134a6857aa9|SHA256|text.exe (Somnia*)|
|fbed7e92caefbd74437d0970921bfd7cb724c98c90efd9b6d0c2ac377751c9e5|SHA256|Ip_scanner.zip|
|06fe57cadb837a4e3b47589e95bb01aec1cfb7ce62fdba1f4323bb471591e1d2|SHA256|Ip_scanner.exe (Themida; Vidar)|
|1e0facd62d1958ccf79e049270061a9fce3223f7986c526f6f3a93ef85180a72|SHA256|Ip_scanner_unpacked.exe (Vidar)|
|3b2e708eaa4744c76a633391cf2c983f4a098b46436525619e5ea44e105355fe|SHA256|DoubleZero|
|931b6b29e13d76a0e2e1e8b6910873d5ff7b88fd8c51cadf46057e47b695f187|SHA256|Endurance|
|BDF8B53D73CA1ED1B649B32A61608B2CF952397EF3D5FC2E6E9F41AD98C40110|SHA256|Cry Wiper|
|91a9180a9cf7674c34ed53a8aa4e36b798334d1f448aeaf1afb9add4fd322b6e|SHA256|Fantasy|
|0ad0cd07ca69d8fd2b075fef6e6dd5e9f7debca92af3a6b84d83e51e23bc182d|SHA256|Bruh Wiper|
|cc213200daf4202e2454dc2c363db04f|MD5|new.exe (CaddyWiper v3)|
|00782ccd65a1e03e3e74ce1e59e752926e0a050818fa195bd7e5a5b359500758|SHA256|new.exe (CaddyWiper v3)|
|54e5773071b193e109cbacc82565c6a9|MD5|upd.exe (ZeroWipe)|
|e3bc3689f01fd431cd2ed368ae91eceaa7c465c2781fa7b7dc2ec9143a404f79|SHA256|upd.exe (ZeroWipe)|
|6aa899b47596323da573fb218f3a8266|MD5|news.bat|
|301b248a8291df6c7f3565a3dac17ee69609f36ef474b4f20eebe134746a9cac|SHA256|news.bat|
|803df907d936e08fbbd06020c411be93|MD5|sdelete.exe (SDelete)|
|e8eaa39e2adfd49ab69d7bb8504ccb82a902c8b48fbc256472f36f41775e594c|SHA256|sdelete.exe (SDelete)|
|3a1070b882d6843fcfa9490c24700bd1|MD5|r.sh (AwfulShred)|
|246607235d560e90590dcf1b0507ab18de74afcc4429d8d5f3ba97eacc92d73f|SHA256|r.sh (AwfulShred)|
|4a5863d34fc99e91af11dd7976c36c27|MD5|audit.sh (BidSwipe)|
|66548ba6ca6d34b7d17e42ab2e1405db1c581a516e0b1a4942d373d6d5396ba4|SHA256|audit.sh (BidSwipe)|
|185[.]220.101.185|IP||
|185[.]220.102.244|IP||
|185[.]220.102.245|IP||
|185[.]220.102.248|IP||
|185[.]220.102.250|IP||
|185[.]220.102.251|IP||
|45[.]154.98.225 |IP||
|77[.]91.123.136|IP||
|80[.]67.167.81|IP||
|194[.]28.172.172|IP||
|194[.]28.172.81|IP||





### Poweshell

    powershell.exe -Enc JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZg[...]xADgALgB0AG0AcAAnAA==
    powershell.exe -Enc JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZg[...]zADEAOAAuAHQAbQBwACcA
    powershell.exe -Enc JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZg[...]5AEEAQgAuAGwAbwBnACcA
    powershell.exe -Enc JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZg[...]2ADQALgBsAG8AZwAnAA==
    $ProgressPreference="SilentlyContinue";copy C:\windows\system32\winevt\logs\Security.evtx C:\windows\temp\b8WTBWCoF5.log > 'C:\windows\temp\TS_4318.tmp'
    $ProgressPreference="SilentlyContinue";copy C:\windows\system32\winevt\logs\Security.evtx C:\windows\temp\b8WTBWCoF5.log > 'C:windowstemp\TS_4318.tmp'
    $ProgressPreference="SilentlyContinue";dnscmd /enumrecords %DOMAIN% . /type A /child > 'C:\windows\temp\BRN3C2AF47629AB.log'
    $ProgressPreference="SilentlyContinue";hostname > 'C:\VLOG\dd_vcredist_x86_20200324195140_001_vcRuntimeAdditional_x64.log'
    icacls.exe C:\Windows\explorer.exe /deny *S-1-1-0:F
    takeown /F C:\Windows\explorer.exe
    

