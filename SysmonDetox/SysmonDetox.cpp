#include <iostream>
#include "SysmonDetoxClass.h"

using namespace std;

int main(){
	SysmonDetox sysmonDetox;
	int sysmonFound = sysmonDetox.SysmonDetector();
	if (sysmonFound == 0) {
		cout << "Sysmon not found" << endl;
		return 0;
	}
	else {
		cout << "\n[!]Sysmon found...\nLet's get information...\n" << endl;
		string configFilePath = "";
		string driverName = "";
		string altitude = "";
		cout << "[!]Dumping sysmon rules...\n";
		sysmonDetox.SysmonDumpRules();
		configFilePath = sysmonDetox.getConfigFilePath();
		driverName = sysmonDetox.getDriverName();
		altitude = sysmonDetox.getAltitude();


		cout << "\n[!]Driver name: " << driverName << endl;
		cout << "\n[!]Altitude: " << altitude << endl;
		cout << "\n[!]Config file path: " << configFilePath << endl;
	}
	
	return 0;
}

