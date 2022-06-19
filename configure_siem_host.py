#!/usr/bin/env python2
import os
import platform
import re
import shutil
import socket
import sys
import subprocess
from glob import glob
from datetime import datetime

DEFAULT_RULES_FILENAME = '00-siem.rules'
BACKUP_SUFFIX = '.backup.%s' % datetime.now().strftime('%m_%d-%H:%M')
TEMPLATE = """
# ignore errors
-i
# delete all rules
-D
# for busy systems
-b 8192
 
# capabilities, xattr, time change
-a always,exit -F arch=b32 -S capset -k pt_siem_api_caps
-a always,exit -F arch=b64 -S capset -k pt_siem_api_caps
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr -k pt_siem_api_xattr
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -k pt_siem_api_xattr
-a always,exit -F arch=b32 -S settimeofday,adjtimex,clock_settime -k pt_siem_api_time
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k pt_siem_api_time
 
# file monitoring
-a always,exit -S all -F path=/etc/shadow -F perm=r -F auid!=-1 -k pt_siem_etc_read
-a always,exit -S all -F path=/etc/sudoers -F perm=r -F auid!=-1 -k pt_siem_etc_read
-a always,exit -S all -F dir=/etc/sudoers.d -F perm=r -F auid!=-1 -k pt_siem_etc_read
-a always,exit -S all -F path=/etc/passwd -F perm=r -F auid!=-1 -k pt_siem_etc_read
-a always,exit -S all -F path=/etc/group -F perm=r -F auid!=-1 -k pt_siem_etc_read
-a always,exit -S all -F path=/etc/security/opasswd -F perm=r -F auid!=-1 -k pt_siem_etc_read
-a always,exit -S all -F dir=/var/log -F perm=rwa -F auid!=-1 -k pt_siem_var_log_access
-w /etc -p wa -k pt_siem_etc_modify
-w /home -p rwa -k pt_siem_home_access
-w /root -p rwa -k pt_siem_home_access
-w /var/spool/cron -p wa -k pt_siem_cron_modify
-w /var/spool/at -p wa -k pt_siem_cron_modify
-w /bin -p wa -k pt_siem_bin_modify
-w /usr/bin -p wa -k pt_siem_bin_modify
-w /sbin -p wa -k pt_siem_bin_modify
-w /usr/sbin -p wa -k pt_siem_bin_modify
-w /usr/local/bin -p wa -k pt_siem_bin_modify
-w /usr/local/sbin -p wa -k pt_siem_bin_modify
-w /usr/libexec -p wa -k pt_siem_bin_modify
-w /lib -p wa -k pt_siem_lib_modify
-w /lib64 -p wa -k pt_siem_lib_modify
-w /usr/lib -p wa -k pt_siem_lib_modify
-w /usr/lib64 -p wa -k pt_siem_lib_modify
-w /boot -p wa -k pt_siem_boot_modify
-w /var/www -p wa -k pt_siem_www_modify
 
# exclude bins
-a never,exit -F exe=/usr/bin/vmtoolsd
-a never,exit -F exe=/usr/sbin/haproxy
-a never,exit -F exe=/usr/sbin/cron
-a never,exit -F exe=/lib/systemd/systemd-timesyncd
-a never,exit -F exe=/lib/systemd/systemd-logind
 
# network activities
-a always,exit -F arch=b32 -S socket -F a0=0x2 -k pt_siem_api_socket
-a always,exit -F arch=b64 -S socket -F a0=0x2 -k pt_siem_api_socket
-a always,exit -F arch=b32 -S socket -F a0=0xA -k pt_siem_api_socket
-a always,exit -F arch=b64 -S socket -F a0=0xA -k pt_siem_api_socket
-a always,exit -F arch=b32 -S socket -F a0=0x11 -k pt_siem_api_socket
-a always,exit -F arch=b64 -S socket -F a0=0x11 -k pt_siem_api_socket
-a always,exit -F arch=b32 -S connect -F a2=0x10 -k pt_siem_api_connect
-a always,exit -F arch=b64 -S connect -F a2=0x10 -k pt_siem_api_connect
-a always,exit -F arch=b32 -S connect -F a2=0x1C -k pt_siem_api_connect
-a always,exit -F arch=b64 -S connect -F a2=0x1C -k pt_siem_api_connect
-a always,exit -F arch=b32 -S accept4 -k pt_siem_api_accept
-a always,exit -F arch=b64 -S accept4 -k pt_siem_api_accept
-a always,exit -F arch=b64 -S accept -k pt_siem_api_accept
-a always,exit -F arch=b32 -S listen -k pt_siem_api_listen
-a always,exit -F arch=b64 -S listen -k pt_siem_api_listen
 
# execute
-a always,exit -F arch=b32 -S execve -F euid>0 -F euid<<UID_MIN> -F key=pt_siem_execve_daemon
-a always,exit -F arch=b32 -S execveat -F euid>0 -F euid<<UID_MIN> -F key=pt_siem_execve_daemon
-a always,exit -F arch=b64 -S execve -F euid>0 -F euid<<UID_MIN> -F key=pt_siem_execve_daemon
-a always,exit -F arch=b64 -S execveat -F euid>0 -F euid<<UID_MIN> -F key=pt_siem_execve_daemon
-a always,exit -F arch=b32 -S execve -k pt_siem_execve
-a always,exit -F arch=b32 -S execveat -k pt_siem_execve
-a always,exit -F arch=b64 -S execve -k pt_siem_execve
-a always,exit -F arch=b64 -S execveat -k pt_siem_execve
 
# kernel modules, process trace, special permissions
-a always,exit -F arch=b32 -S init_module,delete_module -F auid!=-1 -k pt_siem_api_kernel_mods
-a always,exit -F arch=b32 -S finit_module -F auid!=-1 -k pt_siem_api_kernel_mods
-a always,exit -F arch=b64 -S init_module,delete_module -F auid!=-1 -k pt_siem_api_kernel_mods
-a always,exit -F arch=b64 -S finit_module -F auid!=-1 -k pt_siem_api_kernel_mods
-a always,exit -F arch=b32 -S ptrace -k pt_siem_api_ptrace
-a always,exit -F arch=b64 -S ptrace -k pt_siem_api_ptrace
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -k pt_siem_api_setuid
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k pt_siem_api_setuid
"""

def print_help():
    print("""Usage: %s [OPTIONS]...                                                         \n"""
          """                                                                               \n"""
          """Configure host for PT MaxPatrol SIEM.                                          \n"""
          """--help, -h                     print this help page                            \n"""
          """                                                                               \n"""
          """Required:                                                                      \n"""
          """--dst=DST1[,DST2]...           destinations for rsyslog profile, f.i.:         \n"""
          """                                 /var/log/siem.log                             \n"""
          """                                 @remote.server:514                            \n"""
          """                                                                               \n"""
          """Optional:                                                                      \n"""
          """--noconfirm                    do not ask for confirmation                     \n"""
          """--confirm                      always ask for confirmation                     \n"""
          """--quiet                        do not print output                             \n"""
          """--files=FILE1[,FILE2]...       files with auditd rules to be written           \n"""
          """                               If not set these files will be created:         \n"""
          """                                 /etc/audit/audit.rules                        \n"""
          """                                 /etc/audit/rules.d/%s                         \n"""
          """--syslog_service=NAME          name of syslog service                          \n"""
          """                                 (syslogd / rsyslog / rsyslogd)                \n"""
          """--restart                      restart auditd and rsyslog daemons              \n"""
          % (sys.argv[0], DEFAULT_RULES_FILENAME))

def red(prt):
    return '\033[91m%s\033[00m' % prt

def green(prt):
    return '\033[92m%s\033[00m' % prt

def cyan(prt):
    return '\033[96m%s\033[00m' % prt

def write_config(filename, create_new=False):
    def wrapper(func):

        def inner(*args, **kwargs):
            filename_overwritten = kwargs.get('filename', filename)
            try:
                f = open(filename_overwritten)
                content = original = f.read()
                f.close()
            except:
                if create_new:
                    print(cyan('\n%s will be created' % filename_overwritten))
                    f = open(filename_overwritten, 'w')
                    f.close()
                    content = original = ''
                    os.chmod(filename_overwritten, 0o600)
                else:
                    print(red('\n%s not found. Skipping configuration.' % filename_overwritten))
                    if confirm:
                        proceed = raw_input('Continue? [y/N] ').strip() or 'n'
                        if not proceed.lower().startswith('y'):
                            sys.exit()
                    return

            kwargs.update(dict(content=content))
            new_content, colored_content = func(*args, **kwargs)
            changed = original.strip() != new_content.strip()

            if verbose:
                print(cyan('\n%s:' % filename_overwritten))
                if changed:
                    print(colored_content)
                else:
                    print('No changes.')

            if not changed or filename_overwritten not in files_for_backup_cp + files_for_backup_mv:
                return

            if os.path.exists(filename_overwritten) and confirm:
                overwrite = raw_input(
                    'File %s exists. Overwrite? [y/N] ' % filename_overwritten).strip() or 'n'
                if not overwrite.lower().startswith('y'):
                    print(red('Aborted.'))
                    return

            try:
                f = open(filename_overwritten, 'w')
                f.write(new_content)
                f.close()
            except:
                print(red('\nError writing %s. Please ensure that path exists.' % filename_overwritten))

            if verbose:
                print(cyan('File written: %s' % filename_overwritten))

        return inner

    return wrapper

def run_command(command):
    try:
        process = subprocess.Popen(
            command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        return -1
    while True:
        output = process.stdout.readline() + process.stderr.readline()
        if output == '' and process.poll() is not None:
            break
        if output and verbose:
            print(output.strip())
    print('')
    return process.poll()

def gen_auditd_rules(auditd_ver):
    
    # Detecting system architecture
    arch = platform.machine()
    if not arch:
        print("Couldn't detect arch. x86_64 is used")
        arch = 'x86_64'
    if verbose:
        print('Architecture detected: %s' % (arch,))
        
    # Detecting Linux version
    tmp = re.search(r'[\d.]+', platform.uname()[2])
    if tmp:
        linux_ver = tmp.group(0)
        if verbose:
            print('Linux %s detected' % (linux_ver,))
    else:
        print(red("Couldn't detect Linux version."))
        sys.exit()
    linux_ver = tuple(int(v) for v in linux_ver.split('.'))
    
    # Detecting UID_MIN
    f = open('/etc/login.defs')
    content = f.read()
    f.close()
    tmp = re.search(r'^\s*UID_MIN\s+(\d+)', content, re.M)
    if tmp:
        uid_min = tmp.group(1)
    else:
        uid_min = '1000'
    if verbose:
        print('Detected UID_MIN: %s' % (uid_min,))
    # Apply changes
    ruleset = TEMPLATE
    
    if auditd_ver < (2, 6):
        ruleset = re.sub(r'(.*)exe=(.*)', r'# \g<0>', ruleset)
    if arch != 'x86_64':
        ruleset = re.sub(r'(.*)arch=b64(.*)\n', r'', ruleset)
    
    if linux_ver < (3, 8):
        ruleset = re.sub(
            r'(.*)\s+-S\s+finit_module(.*)', r'\g<1>\g<2>', ruleset)
    ruleset = re.sub(r'<UID_MIN>', uid_min, ruleset)
    return ruleset

@write_config('/etc/audit/auditd.conf')
def make_auditd_config(auditd_ver, content):
    lines_added = False
    if auditd_ver < (2, 6):
        log_format = 'RAW'
    else:
        log_format = 'ENRICHED'

    content_colored = content
    settings_map = {
        'log_format': log_format,
        'name_format': 'NUMERIC',
        'disp_qos': 'lossless',
        'write_logs': 'no'
    }

    for key, value in settings_map.items():
        if re.search(r'^\s*%s' % key, content, re.M | re.I):
            reg = re.compile(r'^(\s*%s\s*=\s*)\S+' % key, re.M | re.I)
            content = reg.sub(r'\g<1>%s' % value, content)
            content_colored = reg.sub(green(r'\g<1>%s' % value), content_colored)
        else:
            content += '\n%s = %s' % (key, value)
            content_colored += green('\n%s = %s' % (key, value))
            lines_added = True

    if lines_added:
        content += '\n'
    return content, content_colored


@write_config('/etc/hosts')
def make_hosts_config(content):
    hostname = socket.gethostname()
    try:
        ip_addr = socket.gethostbyname(hostname)
    except:
        ip_addr = '127.0.0.1'
    if ip_addr.startswith('127.'):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('1.1.1.1', 53))
        ip_addr = sock.getsockname()[0]
        sock.close()
    content_colored = content

    if not re.search(r'^\s*%s\s+%s.*$' % (ip_addr, hostname), content, re.M):
        reg = re.compile(r'^[^#\n]+\S+\s+%s.*$' % hostname, re.M | re.I)
        content = reg.sub(r'#\g<0>', content)
        content_colored = reg.sub(green(r'#\g<0>'), content_colored)
        content += '\n%s %s\n' % (ip_addr, hostname)
        content_colored += green('\n%s %s\n') % (ip_addr, hostname)
    return content, content_colored

@write_config('/etc/audisp/plugins.d/syslog.conf')
def make_audispd_config(content, **kwargs):
    reg = re.compile(r'^[^#\n]*(\bactive\s*=\s*)\S+', re.M | re.I)
    content = reg.sub(r'\g<1>yes', content)
    content_colored = reg.sub(green(r'\g<1>yes'), content)
    return content, content_colored

@write_config('/etc/rsyslog.conf')
def make_rsyslog_config(content):
    content_colored = content
    lines_added = False

    if not (
            re.search(r'^\s*\$IncludeConfig\s+/etc/rsyslog\.d/\*\.conf',
                      content, re.M | re.I) or
            re.search(r'^\s*include\(file="\/etc\/rsyslog\.d\/\*\.conf" mode="optional"\)',
                      content, re.M | re.I)):
        content += '\n$IncludeConfig /etc/rsyslog.d/*.conf'

    settings_map = {
        'RepeatedMsgReduction': 'off',
        'ActionQueueType': 'LinkedList',
        'ActionQueueFileName': 'syslog_queue',
        'ActionResumeRetryCount': '-1',
        'ActionQueueSaveOnShutdown': 'on',
        'ActionQueueMaxDiskSpace': '1024m',
        'ActionQueueTimeoutEnqueue': '0',
    }

    if os.path.exists('/etc/systemd/journald.conf'):
        settings_map.update({'imjournalRatelimitInterval': '15'})
        make_journald_config()
    else:
        settings_map.update({
            'SystemLogRateLimitBurst': '20000',
            'SystemLogRateLimitInterval': '15'
        })

    for setting, value in settings_map.items():
        if re.search(r'^(\s*\$%s\s+)\S+' % setting, content, re.M | re.I):
            content = re.sub(
                r'(\s*\$%s\s+)\S+' % setting,
                r'\g<1>%s' % value,
                content)
            content_colored = re.sub(
                r'(\s*\$%s\s+)\S+' % setting,
                green(r'\g<1>%s' % value),
                content_colored)
        else:
            content += '\n$%s %s' % (setting, value)
            content_colored += green('\n$%s %s' % (setting, value))
            lines_added = True

    if lines_added:
        content += '\n'
    return content, content_colored

@write_config('/etc/rsyslog.d/10-siem.conf', create_new=True)
def make_rsyslog_profile_config(destinations, content):
    content_colored = content
    siem_profile = '\n'.join([
        '*.info;mail.none;lpr.none;news.none;uucp.none;cron.none %s' % dst
        for dst in destinations])
    siem_profile += '\n:programname, contains, "audisp", stop'

    if siem_profile not in content:
        content += '\n' + siem_profile
        content_colored += '\n' + green(siem_profile)
    return content, content_colored

@write_config('/etc/syslog.conf')
def make_syslogd_profile_config(destinations, content):
    content_colored = content
    siem_profile = '\n'.join([
        '*.info;mail.none;lpr.none;news.none;uucp.none;cron.none %s' % dst
        for dst in destinations])
    if siem_profile not in content:
        content += '\n' + siem_profile
        content_colored += '\n' + green(siem_profile)
    return content, content_colored

@write_config('/etc/systemd/journald.conf')
def make_journald_config(content):
    lines_added = False
    content_colored = content
    settings_map = {
        'RateLimitBurst': '20000'
    }

    for key, value in settings_map.items():
        if re.search(r'^\s*%s' % key, content, re.M | re.I):
            reg = re.compile(r'^(\s*%s\s*=\s*)\S+' % key, re.M | re.I)
            content = reg.sub(r'\g<1>%s' % value, content)
            content_colored = reg.sub(green(r'\g<1>%s' % value), content_colored)
        else:
            content += '\n%s=%s' % (key, value)
            content_colored += green('\n%s=%s' % (key, value))
            lines_added = True

    if lines_added:
        content += '\n'

    return content, content_colored

def detect_auditd_verion():
    try:
        proc = subprocess.Popen(
            ['auditctl', '-v'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    except Exception:
        print(red("Couldn't execute 'auditctl -v'"))
        sys.exit()
    output, error = proc.communicate()
    if error and verbose:
        print(error)
    tmp = re.search(r'[\d.]+', output)
    if tmp:
        auditd_ver = tmp.group(0)
        if verbose:
            print('auditd %s detected' % (auditd_ver,))
    else:
        print(red("Couldn't detect auditd version."))
        sys.exit()
    return tuple(int(v) for v in auditd_ver.split('.'))

def backup_files_cp(files):
    files = list(set().union(*[glob(file) for file in files]))
    for backup_file in files:
        shutil.copy2(backup_file, backup_file + BACKUP_SUFFIX)
    if verbose and files:
        print(cyan('\nOld files copied with suffix "%s":' % BACKUP_SUFFIX))
        print('\n'.join(sorted(files)))

def backup_files_mv(files):
    files = list(set().union(*[glob(file) for file in files]))
    for backup_file in files:
        os.rename(backup_file, backup_file + BACKUP_SUFFIX)
    if verbose and files:
        print(cyan('\nOld files moved with suffix "%s":' % BACKUP_SUFFIX))
        print('\n'.join(sorted(files)))

def restore_files(files):
    files = list(set().union(*[glob(file) for file in files]))
    for backup_file in files:
        os.rename(backup_file + BACKUP_SUFFIX, backup_file)
    if verbose and files:
        print(red('\nError! Revert changes:\n%s\n' % '\n'.join(sorted(files))))

def main():
    global verbose
    global confirm

    argv = sys.argv[1:]
    if '-h' in argv or '--help' in argv:
        print_help()
        sys.exit()

    if '--noconfirm' in argv and '--confirm' not in argv:
        confirm = False
    else:
        confirm = True

    for arg in argv:
        tmp = re.match(r'--files?=(\S+)', arg)
        if tmp:
            rulefiles = tmp.group(1).split(',')
            break
    else:
        rulefiles = [
            '/etc/audit/audit.rules',
            '/etc/audit/rules.d/%s' % (DEFAULT_RULES_FILENAME,)]

    for arg in argv:
        tmp = re.match(r'--syslog_service=(\S+)', arg)
        if tmp:
            syslog_service = tmp.group(1)
            break
    else:
        syslog_service = 'rsyslog'
    if syslog_service not in ['syslogd', 'rsyslogd', 'rsyslog']:
        print(red('%s not supported' % syslog_service))
        sys.exit()

    for arg in argv:
        tmp = re.match(r'--dst=(\S+)', arg)
        if tmp:
            destinations = tmp.group(1).split(',')
            break
    else:
        print(red('\n--dst: parameter not found'))
        print_help()
        sys.exit()

    if '--quiet' in argv:
        verbose = False
    else:
        verbose = True

    if '--restart' in argv:
        restart_daemon = True
    else:
        restart_daemon = False

    if os.getuid() != 0:
        print(red('Root privileges required!'))
        sys.exit()

    auditd_version = detect_auditd_verion()
    audispd_config_location = '/etc/audisp/plugins.d/syslog.conf'
    if auditd_version >= (3, 0):
        audispd_config_location = '/etc/audit/plugins.d/syslog.conf'

    # Start configuration
    global files_for_backup_mv
    global files_for_backup_cp
    files_for_backup_mv = [
        '/etc/audit/audit.rules', '/etc/audit/rules.d/*.rules']
    files_for_backup_cp = [
        '/etc/audit/auditd.conf', audispd_config_location,
        '/etc/hosts',
        '/etc/rsyslog.conf', '/etc/rsyslog.d/10-siem.conf', '/etc/syslog.conf',
        '/etc/systemd/journald.conf']

    backup_files_mv(files_for_backup_mv)
    backup_files_cp(files_for_backup_cp)

    try:
        if verbose:
            print(cyan('\nWriting config files...'))
            if confirm:
                print(red('PLEASE READ CONFIG FILES CONTENT FIRST!'))

        rules = gen_auditd_rules(auditd_version)
        for rulefile in rulefiles:
            if os.path.exists(rulefile) and confirm:
                overwrite = raw_input(
                    'File %s exists. Overwrite? [y/N] ' % rulefile).strip() or 'n'
                if not overwrite.lower().startswith('y'):
                    print(red('Aborted.'))
                    continue
            f = open(rulefile, 'w')
            f.write(rules)
            f.close()
            if verbose:
                print(cyan('File written: %s' % rulefile))
        make_auditd_config(auditd_version)
        make_audispd_config(filename=audispd_config_location)
        make_hosts_config()
        if syslog_service in ['rsyslog', 'rsyslogd']:
            make_rsyslog_config()
            if not os.path.exists('/etc/rsyslog.d/'):
                os.makedirs('/etc/rsyslog.d/')
            make_rsyslog_profile_config(destinations)
        elif syslog_service in ['syslogd']:
            make_syslogd_profile_config(destinations)

    except Exception as e:
        print(red('\nError!'))
        restore_files(files_for_backup_mv + files_for_backup_cp)
        raise e

    if restart_daemon:
        if verbose:
            print(cyan('\nRestarting services...'))
        run_command('service auditd restart')
        run_command('service %s restart' % syslog_service)

    print(green('\nCompleted!'))

if __name__ == '__main__':
    main()