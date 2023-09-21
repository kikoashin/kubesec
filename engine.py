from pandas import json_normalize
import json
from string import Template
import glob_rules
import os


t_qualifier = '"DENIED"'
t_filename = 'test.txt'
#t_profilename = '"/usr/sbin/cups-browsed"'
#t_profilename = '"snap.snap-store.ubuntu-software"'
t_profilename = '"snap.docker.compose"'
base_template = Template("""
#include <tunables/global>

profile $docker_exe flags=(attach_disconnected, mediate_deleted) {
\t#include <abstractions/base>

\t$capability
\t$network
\t$fileExe
\t$file
\t# pivot_root,
\tsignal (send,receive) peer=@{profile_name},
\tdeny @{PROC}/* w,   # deny write for all files directly in /proc (not in a subdir)
\t# deny write to files not in /proc/<number>/** or /proc/sys/**
\tdeny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
\tdeny @{PROC}/sys/[^k]** w,  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)
\tdeny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,  # deny everything except shm* in /proc/sys/kernel/
\tdeny @{PROC}/sysrq-trigger rwklx,
\tdeny @{PROC}/kcore rwklx,

\tdeny mount,

\tdeny /sys/[^f]*/** wklx,
\tdeny /sys/f[^s]*/** wklx,
\tdeny /sys/fs/[^c]*/** wklx,
\tdeny /sys/fs/c[^g]*/** wklx,
\tdeny /sys/fs/cg[^r]*/** wklx,
\tdeny /sys/firmware/** rwklx,
\tdeny /sys/kernel/security/** rwklx,

\tptrace (trace,read,tracedby,readby) peer=@{profile_name},
}
""")


current_directory = os.getcwd()
profile_directory = os.path.join(current_directory, 'profile')
if not os.path.exists(profile_directory):
    os.makedirs(profile_directory)

def globber(dfFile):
        dfFile['name'] = dfFile['name'].str.replace('\"','')
        dfFile['requested_mask'] = dfFile['requested_mask'].str.replace('\"','')
        dfFile['name'] = glob_rules.genSpecAccessPath(dfFile['name'])
        dfFile['name'] = glob_rules.genGlobalAccessPath(dfFile['name'])
        dfFile['name'] = glob_rules.genFullAccessPath(dfFile['name'])
        dfFile['name'] = glob_rules.genRandomFilePath(dfFile['name'])
        dfFile['requested_mask'] = glob_rules.genPermission(dfFile['requested_mask'])
        return dfFile

def profileNameFixer(profileName):
    profileName = profileName.replace('\"', '')
    if '/' in profileName:
        profileName = profileName.split('/',1)[1].replace('/','.')
    return profileName

def logReader(fileName, q, profileName):
    logCap = []
    logNet = []
    logFile = []
    logFileExe = []
    with open(fileName) as f:
        for line in f:
            data_json = json.loads(line)
            if "apparmor" in data_json and data_json["apparmor"] == q:
                if data_json["profile"] == profileName:
                    if "capname" in data_json:
                        logCap.append(json.loads(line))
                    elif "sock_type" in data_json:
                        logNet.append(json.loads(line))
                    elif "fsuid" in data_json and "info" in data_json:
                        logFileExe.append(json.loads(line))
                    else:
                        logFile.append(json.loads(line))
    # print(logCap)
    # print(logFile)
    outputDfCap = json_normalize(logCap)
    outputDfNet = json_normalize(logNet)
    outputDfFileExe = json_normalize(logFileExe)
    outputDfFile = json_normalize(logFile)

    profile = profileNameFixer(profileName)

    outputCapRule = capRuleGen(outputDfCap, profile)
    outputNetRule = netRuleGen(outputDfNet, profile)
    outputFileExeRule = fileExeRuleGen(outputDfFileExe, profile)
    outputFileRule = fileRuleGen(outputDfFile, profile)

    return outputCapRule, outputNetRule, outputFileExeRule, outputFileRule, profile

def capRuleGen(df_cap, profile_name):
    capRule = ''
    if not df_cap.empty:       
        df_cap = df_cap.drop_duplicates('capname')
        df = 'capability ' + df_cap['capname'].str.replace('\"', '') + ','
        cap_list = df.tolist()
        for v in cap_list:
            capRule = capRule + v + '\n' + '\t'
        print("capability policies are:\n", capRule)
        df.to_csv(profile_directory+"/cap_rule_{}.txt".format(profile_name), header=False, index=False)
    else:
        print("no capability found from the logs")
    return capRule

def netRuleGen(df_net, profile_name):
    netRule = ''
    if not df_net.empty:       
        df_net = df_net.drop_duplicates(['sock_type','family'])
        df = 'network ' + df_net[['family', 'sock_type']].agg(" ".join, axis=1).str.replace('\"', '') + ','
        net_list = df.tolist()
        for v in net_list:
            netRule = netRule + v + '\n' + '\t'
        print("network policies are:\n", netRule)
        df.to_csv(profile_directory+"/net_rule_{}.txt".format(profile_name), header=False, index=False)
    else:
        print("no network access found from the logs")
    return netRule

def fileExeRuleGen(df_fileExe, profile_name):
    fileExeRule = ''
    if not df_fileExe.empty:
        dfAfterGlobbing = globber(df_fileExe)
        df_fileExe['info'] = df_fileExe['info'].str.replace('\"','')
        dfAfterGlobbing = dfAfterGlobbing.drop_duplicates(['name','requested_mask','info'])
        dfAfterGlobbing['info'] = dfAfterGlobbing['info'].str.replace(" fallback", "", regex=False) 
        df = dfAfterGlobbing[['name', 'info']].agg(" ".join, axis=1) + ','
        fileExe_list = df.tolist()
        for v in fileExe_list:
            fileExeRule = fileExeRule + v + '\n' + '\t'
        print("file policies are:\n", fileExeRule)
        df.to_csv(profile_directory+"/fileExe_rule_{}.txt".format(profile_name), header=False, index=False)
    else:
        print("no file exe accesses found from the logs")
    return fileExeRule

def fileRuleGen(df_file, profile_name):
    fileRule = ''
    if not df_file.empty:
        dfAfterGlobbing = globber(df_file)
        dfAfterGlobbing = dfAfterGlobbing.drop_duplicates(['name','requested_mask'])
        df = dfAfterGlobbing[['name', 'requested_mask']].agg(" ".join, axis=1) + ','
        file_list = df.tolist()
        for v in file_list:
            fileRule = fileRule + v + '\n' + '\t'
        print("file policies are:\n", fileRule)
        df.to_csv(profile_directory+"/file_rule_{}.txt".format(profile_name), header=False, index=False)
    else:
        print("no file accesses found from the logs")
    return fileRule





def main():
    cap, net, fileExe, file, p = logReader(t_filename, t_qualifier, t_profilename)

    with open(profile_directory + '/' + p, 'w') as f:
        f.write(base_template.safe_substitute(docker_exe=p, capability=cap, network=net, fileExe=fileExe, file=file))
    # print("DfCap for profile {} is {}".format(t_profilename, DfCap))
    # print("DfNet for profile {} is {}".format(t_profilename, DfNet))
    # print("DfFile for profile {} is {}".format(t_profilename, DfFile))

if __name__ == "__main__":
    main()