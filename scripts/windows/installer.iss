#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef StageDir
  #error StageDir must point to the release payload
#endif
#ifndef OutputDir
  #define OutputDir "..\..\release"
#endif

[Setup]
AppId={{6C940285-89BD-420C-AB4B-C0E691214873}
AppName=MCP SSH K8s
AppVersion={#AppVersion}
AppPublisher=edward1987
AppPublisherURL=https://github.com/edward1987/mcp-ssh-k8s
AppSupportURL=https://github.com/edward1987/mcp-ssh-k8s/issues
AppUpdatesURL=https://github.com/edward1987/mcp-ssh-k8s/releases
DefaultDirName={autopf}\MCP SSH K8s
DefaultGroupName=MCP SSH K8s
DisableProgramGroupPage=yes
DisableDirPage=no
DisableWelcomePage=no
LicenseFile=..\..\LICENSE
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
PrivilegesRequired=admin
WizardStyle=modern
WizardSizePercent=115
SetupIconFile={#StageDir}\app.ico
UninstallDisplayIcon={app}\app.ico
OutputDir={#OutputDir}
OutputBaseFilename=mcp-ssh-k8s-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
CloseApplications=no
RestartApplications=no
UninstallDisplayName=MCP SSH K8s
VersionInfoDescription=MCP SSH K8s Windows Installer
VersionInfoProductName=MCP SSH K8s

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "romanian"; MessagesFile: "languages\Romanian.isl"

[CustomMessages]
english.ServiceTask=Start automatically with Windows as a service
english.ServiceGroup=Windows startup:
english.DesktopTask=Create a desktop shortcut
english.OpenApp=Open MCP SSH K8s
english.DataTitle=Your vault and local data
english.DataSubtitle=Use an existing database or choose a folder for a new vault.
english.DataPrompt=Select the DATA folder containing vault.json, not the application folder. Existing hosts, keys, tokens and audit history are reused. The master password remains the same. Uninstalling keeps your data.
english.DataLabel=Data folder:
english.ExistingData=Existing vault detected. It will be reused and backed up before installation.
english.NewData=No vault.json in this folder. A new vault will be created at first launch.
english.StopFailed=Could not prepare the installation. Close the previous MCP SSH instance and retry.
english.ConfigFailed=Configuration failed. Your data was preserved. Details:
english.StopShortcut=Stop MCP SSH K8s (manual mode)
english.GuideShortcut=Installation and data guide
english.ServicesShortcut=Windows Services
english.DataInvalid=Choose an absolute local data folder outside the application directory. Drive roots and percent signs are not allowed.
romanian.ServiceTask=Porneste automat cu Windows ca serviciu
romanian.ServiceGroup=Pornire Windows:
romanian.DesktopTask=Creeaza o scurtatura pe desktop
romanian.OpenApp=Deschide MCP SSH K8s
romanian.DataTitle=Vault-ul si datele tale
romanian.DataSubtitle=Foloseste baza existenta sau alege un folder pentru un vault nou.
romanian.DataPrompt=Selecteaza folderul DATA care contine vault.json, nu folderul aplicatiei. Serverele, cheile, tokenurile si istoricul existente vor fi refolosite. Parola master ramane aceeasi. Dezinstalarea pastreaza datele.
romanian.DataLabel=Folder de date:
romanian.ExistingData=Am gasit un vault existent. Va fi refolosit si se va face backup inainte de instalare.
romanian.NewData=Nu exista vault.json in acest folder. Vei crea un vault nou la prima pornire.
romanian.StopFailed=Instalarea nu poate continua. Inchide instanta MCP SSH existenta si reincearca.
romanian.ConfigFailed=Configurarea a esuat. Datele tale au fost pastrate. Detalii:
romanian.StopShortcut=Opreste MCP SSH K8s (mod manual)
romanian.GuideShortcut=Ghid de instalare si pastrare a datelor
romanian.ServicesShortcut=Servicii Windows
romanian.DataInvalid=Alege un folder local absolut, in afara folderului aplicatiei. Radacina discului si semnul procent nu sunt permise.

[Tasks]
Name: "service"; Description: "{cm:ServiceTask}"; GroupDescription: "{cm:ServiceGroup}"; Flags: unchecked
Name: "desktopicon"; Description: "{cm:DesktopTask}"; Flags: unchecked

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "configure.ps1"; Flags: dontcopy

[Icons]
Name: "{group}\MCP SSH K8s"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\launch.ps1"""; IconFilename: "{app}\app.ico"
Name: "{autodesktop}\MCP SSH K8s"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\launch.ps1"""; IconFilename: "{app}\app.ico"; Tasks: desktopicon
Name: "{group}\{cm:StopShortcut}"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\stop.ps1"""; IconFilename: "{app}\app.ico"
Name: "{group}\{cm:GuideShortcut}"; Filename: "{app}\docs\WINDOWS_INSTALL.md"
Name: "{group}\{cm:ServicesShortcut}"; Filename: "{sys}\services.msc"

[Registry]
Root: HKLM; Subkey: "Software\MCP SSH K8s"; ValueType: string; ValueName: "DataDir"; ValueData: "{code:GetDataDir}"; Flags: uninsdeletekey

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\launch.ps1"""; Description: "{cm:OpenApp}"; Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\configure.ps1"" -Action Uninstall -InstallDir ""{app}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveMcpSshService"

[UninstallDelete]
Type: files; Name: "{app}\mcp-ssh-service.xml"
Type: files; Name: "{app}\mcp-ssh-service.wrapper.log"

[Code]
var
  DataPage: TInputDirWizardPage;
  DataStatus: TNewStaticText;

function GetDataDir(Param: String): String;
begin
  Result := RemoveBackslashUnlessRoot(Trim(DataPage.Values[0]));
end;

procedure UpdateDataStatus(Sender: TObject);
begin
  if FileExists(AddBackslash(GetDataDir('')) + 'vault.json') then
    DataStatus.Caption := CustomMessage('ExistingData')
  else
    DataStatus.Caption := CustomMessage('NewData');
end;

function DefaultDataDir: String;
var
  Candidate, Parent: String;
  I: Integer;
begin
  if RegQueryStringValue(HKLM, 'Software\MCP SSH K8s', 'DataDir', Result) then Exit;
  Result := GetEnv('MCP_SSH_DATA');
  if (Result <> '') and FileExists(AddBackslash(Result) + 'vault.json') then Exit;
  { Detect a checkout near the installer, without baking any developer path into the release. }
  Parent := ExpandConstant('{src}');
  for I := 0 to 3 do begin
    Candidate := AddBackslash(Parent) + 'data';
    if FileExists(AddBackslash(Candidate) + 'vault.json') then begin
      Result := Candidate;
      Exit;
    end;
    Parent := ExtractFileDir(Parent);
  end;
  Result := ExpandConstant('{commonappdata}\MCP SSH K8s\data');
end;

procedure InitializeWizard;
begin
  DataPage := CreateInputDirPage(wpSelectDir, CustomMessage('DataTitle'), CustomMessage('DataSubtitle'), CustomMessage('DataPrompt'), False, '');
  DataPage.Add(CustomMessage('DataLabel'));
  DataPage.Values[0] := ExpandConstant('{param:DATADIR|' + DefaultDataDir + '}');
  DataStatus := TNewStaticText.Create(WizardForm);
  DataStatus.Parent := DataPage.Surface;
  DataStatus.Top := DataPage.Edits[0].Top + DataPage.Edits[0].Height + ScaleY(16);
  DataStatus.Width := DataPage.SurfaceWidth;
  DataStatus.Height := ScaleY(56);
  DataStatus.WordWrap := True;
  DataPage.Edits[0].OnChange := @UpdateDataStatus;
  UpdateDataStatus(nil);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  DataPath, AppPath: String;
begin
  Result := True;
  if CurPageID = DataPage.ID then begin
    DataPath := Lowercase(AddBackslash(GetDataDir('')));
    AppPath := Lowercase(AddBackslash(ExpandConstant('{app}')));
    if (Length(DataPath) <= 3) or (Copy(DataPath, 2, 2) <> ':\') or
       (Pos(AppPath, DataPath) = 1) or (Pos('%', DataPath) > 0) then begin
      MsgBox(CustomMessage('DataInvalid'), mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function RunConfiguration(Action, ScriptFile: String; var Error: String): Boolean;
var
  Args, ErrorPath: String;
  ErrorText: AnsiString;
  ExitCode, ServiceFlag: Integer;
begin
  ErrorPath := ExpandConstant('{tmp}\mcp-ssh-error.txt');
  DeleteFile(ErrorPath);
  ServiceFlag := 0;
  if WizardIsTaskSelected('service') then ServiceFlag := 1;
  Args := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptFile +
    '" -Action ' + Action + ' -InstallDir "' + ExpandConstant('{app}') +
    '" -DataDir "' + GetDataDir('') + '" -EnableService ' + IntToStr(ServiceFlag) +
    ' -ErrorFile "' + ErrorPath + '"';
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, ExitCode);
  Result := Result and (ExitCode = 0);
  if not Result then begin
    if LoadStringFromFile(ErrorPath, ErrorText) then Error := UTF8Decode(ErrorText)
    else Error := CustomMessage('StopFailed');
    Log(Error);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  ExtractTemporaryFile('configure.ps1');
  if RunConfiguration('Prepare', ExpandConstant('{tmp}\configure.ps1'), Result) then Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Error: String;
begin
  if CurStep = ssPostInstall then
    if not RunConfiguration('Configure', ExpandConstant('{app}\configure.ps1'), Error) then
      RaiseException(CustomMessage('ConfigFailed') + #13#10 + Error);
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  UpdateDataStatus(nil);
  Result := MemoDirInfo + NewLine + NewLine + CustomMessage('DataLabel') + NewLine +
    Space + GetDataDir('') + NewLine + Space + DataStatus.Caption + NewLine + NewLine + MemoTasksInfo;
end;
