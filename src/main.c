
#include "getconf.h"
#include "main.h"

//执行ping, 判读返回状态
int ping_status(char *ip)
{
    int i, status;
    pid_t pid;
    printf(">>>>>>>>>>>>> ping_status\n ");
    // 不同则循环检测多次
    for (i = 0; i < 4; ++i)
    {
        sleep(2);
        // 新建一个进程来执行ping命令
        if ((pid = vfork()) < 0)
        {
            printf("vfork error");
            continue;
        }
 
        if (pid == 0)
        {
            if ( execlp("ping", "ping","-c","1",ip, (char*)0) < 0)
            {
                printf("execlp error\n");
                return -1;
            }
        }
 
        waitpid(pid, &status, 0);
 
        // 相等说明正常
        if (status == 0)
        {
            printf("Ping OK!\n");
            //return 0;
        }
    }
 
    return -1;
}

//函数:通过文件锁防止程序多次运行
void AvoidMultiRun()
{

    LOCK_FILE = open("/tmp/single_proc.lock", O_CREAT|O_RDWR, 0666);
    int rc = flock(LOCK_FILE, LOCK_EX|LOCK_NB);
    if (rc)
    {
        if (EWOULDBLOCK == errno)
        {
            printf("Only one programme can be run at the same time\n");
            exit(0);
        }
    }
}

//函数:调用shell命令
void* MyShell(const char *fmt, ...)  
{  
	//存储需要执行的shell命令的缓存
    char shell_buf[SHELL_BUFF_LEN];
    char tmp_buf[SHELL_BUFF_LEN];
    memset(&shell_buf, 0, sizeof(shell_buf));
    memset(&tmp_buf, 0, sizeof(tmp_buf));

    //将传进来的参数放到shell_buf中
    va_list args;   
    va_start(args, fmt);  
    vsnprintf(shell_buf, SHELL_BUFF_LEN, fmt, args);

    //必须调用的一步  
    va_end(args);

	//定义读取shell命令的文件指针
	FILE * fp;
	fp = popen(shell_buf, "r");
	fread(tmp_buf, sizeof(tmp_buf), 1, fp);

	//动态分配一块内存给shell命令的返回值
	char* ret_str = (char *) malloc(strlen(tmp_buf)+1);
	//char* ret_str;
	//ret_str = (char *) malloc(strlen(tmp_buf)+1);
	if (!ret_str)
	{
		perror("malloc");
		return NULL;
	}
	memset(ret_str, 0, strlen(tmp_buf)+1);

	//将读到的返回值放入分配的内存中
	strncpy(ret_str, tmp_buf, strlen(tmp_buf));

	pclose(fp);
    return ret_str;  
}

//函数:MAC地址合法性判断
int RegexEXE(const char *regex_pattern, const char *to_match)
{
    regex_t r;
    int ret;
    int match;
    char errmsg[128];

    if(regcomp(&r, regex_pattern, REG_EXTENDED | REG_NEWLINE)) {
        printf("[%s]:regcomp failed!\n", __FUNCTION__);
        regfree(&r);
        return FALSE;
    }

    ret = regexec(&r, to_match, 0, NULL, 0);
    if(!ret) {
        match = 1;
        printf("[%s]:Legal MAC!\n", __FUNCTION__);
    } else if(ret == REG_NOMATCH) {
        match = 0;
        printf("[%s]:Illegal MAC!\n", __FUNCTION__);
    } else {
        regerror(ret, &r, errmsg, sizeof(errmsg));
        printf("[%s]:Regexec failed: %s!\n", __FUNCTION__, errmsg);
        regfree(&r);
        return FALSE;
    }

    regfree(&r);
    return match;
}

//API:给主函数调用的检查MAC合法性
int CheckMac(const char *mac)
{
    int match;
    const char validMacAddress[] = "^([a-fA-F0-9]{2}:){5}([a-fA-F0-9]{2})$";
    printf("[%s]:Judging %s\n",__FUNCTION__, mac);
    match = RegexEXE(validMacAddress, mac);
    if(match != 1) {
        return FALSE;
    } 
    return 0;
}

//函数:初始化一些必须的变量
void Init(struct NetInfo *structptr)
{
    GetProfileString(conf_path, productname, "GatewayIP", structptr->GatewayIP);

    GetProfileString(conf_path, productname, "FAP_2G4_MAC", structptr->FAP_2G4_MAC);
    if( CheckMac(structptr->FAP_2G4_MAC) == FALSE )
    {
        memset(structptr->FAP_2G4_MAC, 0, sizeof(structptr->FAP_2G4_MAC));
        exit(0);          
    }

    GetProfileString(conf_path, productname, "FAP_5G_MAC", structptr->FAP_5G_MAC);
    if( CheckMac(structptr->FAP_5G_MAC) == FALSE )
    {
        memset(structptr->FAP_5G_MAC, 0, sizeof(structptr->FAP_5G_MAC));
        exit(0); 
    }

    GetProfileString(conf_path, productname, "RE_2G4_MAC", structptr->RE_2G4_MAC);
    if( CheckMac(structptr->RE_2G4_MAC) == FALSE )
    {
        memset(structptr->RE_2G4_MAC, 0, sizeof(structptr->RE_2G4_MAC));
        exit(0); 
    }

    GetProfileString(conf_path, productname, "RE_5G_MAC", structptr->RE_5G_MAC);
    if( CheckMac(structptr->RE_5G_MAC) == FALSE )
    {
        memset(structptr->RE_5G_MAC, 0, sizeof(structptr->RE_5G_MAC));
        exit(0); 
    }

    GetProfileString(conf_path, productname, "FAP_Guest_2G4_MAC", structptr->FAP_Guest_2G4_MAC);
    if( CheckMac(structptr->FAP_Guest_2G4_MAC) == FALSE )
    {
        memset(structptr->FAP_Guest_2G4_MAC, 0, sizeof(structptr->FAP_Guest_2G4_MAC));
        exit(0); 
    }

    GetProfileString(conf_path, productname, "FAP_Guest_5G_MAC", structptr->FAP_Guest_5G_MAC);
    if( CheckMac(structptr->FAP_Guest_5G_MAC) == FALSE )
    {
        memset(structptr->FAP_Guest_5G_MAC, 0, sizeof(structptr->FAP_Guest_5G_MAC));
        exit(0); 
    }

    GetProfileString(conf_path, productname, "RE_Guest_2G4_MAC", structptr->RE_Guest_2G4_MAC);
    if( CheckMac(structptr->RE_Guest_2G4_MAC) == FALSE )
    {
        memset(structptr->RE_Guest_2G4_MAC, 0, sizeof(structptr->RE_Guest_2G4_MAC));
        exit(0); 
    }

    GetProfileString(conf_path, productname, "RE_Guest_5G_MAC", structptr->RE_Guest_5G_MAC);
    if( CheckMac(structptr->RE_Guest_5G_MAC) == FALSE )
    {
        memset(structptr->RE_Guest_5G_MAC, 0, sizeof(structptr->RE_Guest_5G_MAC));
        exit(0); 
    }

    GetProfileString(conf_path, productname, "2G_SSID", structptr->MAIN_2G_SSID);
    GetProfileString(conf_path, productname, "5G_SSID", structptr->MAIN_5G_SSID);
    GetProfileString(conf_path, productname, "Guest_2G_SSID", structptr->Guest_2G_SSID);
    GetProfileString(conf_path, productname, "Guest_5G_SSID", structptr->Guest_5G_SSID);

    GetProfileString(conf_path, productname, "KEY", structptr->MAIN_KEY);
    GetProfileString(conf_path, productname, "Guest_KEY", structptr->Guest_KEY);  

    printf("FAP_2G4_MAC:%s\nFAP_5G_MAC:%s\nRE_2G4_MAC:%s\nRE_2G4_MAC:%s\nFAP_Guest_2G4_MAC:%s\nFAP_Guest_5G_MAC:%s\nRE_Guest_2G4_MAC:%s\nRE_Guest_5G_MAC:%s\n2G_SSID:%s\n5G_SSID:%s\nGuest_2G_SSID:%s\nGuest_5G_SSID:%s\nKEY:%S\nGuest_KEY:%s\n",
                            structptr->FAP_2G4_MAC, 
                            structptr->FAP_5G_MAC,
                            structptr->RE_2G4_MAC,
                            structptr->RE_5G_MAC,
                            structptr->FAP_Guest_2G4_MAC,
                            structptr->FAP_Guest_5G_MAC,
                            structptr->RE_Guest_2G4_MAC,
                            structptr->RE_Guest_5G_MAC,
                            structptr->MAIN_2G_SSID,
                            structptr->MAIN_5G_SSID,
                            structptr->Guest_2G_SSID,
                            structptr->Guest_5G_SSID,
                            structptr->MAIN_KEY,
                            structptr->Guest_KEY);
    //TBD:记得尝试一下不配置SSID，只配置BSSID能否成功连接

}

//函数:扫描周围AP
void Scan(struct NetInfo *structptr)
{   
    //最多尝试10次扫描周围AP
    int count_1 = 10;
    while(count_1)
    {      
        //如果扫描的结果不是OK，则等待5秒，接着扫描
        if ( 0 != strncmp("OK", (char*)MyShell("wpa_cli -i wlan0 scan"), 2) )
        {
            sleep(5);
            count_1 --;
            printf("Trying another %d times to scan\n", count_1);
        }
        //如果扫描的结果是OK,则获取当前的扫描结果,并判断输入的MAC地址是否存在于周围环境中
        //若存在,继续,反之继续扫描
        else
        {
            //printf("%s", MyShell("wpa_cli -i wlan0 scan_result | grep '%s'", FAP_MAC));
            if ( strlen ( (char *)MyShell("wpa_cli -i wlan0 scan_result | grep '%s'", structptr->FAP_2G4_MAC) )  == 0
                || strlen ( (char *)MyShell("wpa_cli -i wlan0 scan_result | grep '%s'", structptr->RE_2G4_MAC) )  == 0
               )
            {
                printf("MAC doesn't exist... Retrying \n");
            }
            else
                break;
            
        }
    }
}

//新增一个网络,返回句柄
int AddNetwork()
{
    //获取新网络句柄
    char *s_network_num = (char *)MyShell("wpa_cli -i wlan0 add_network");
    int i_network_num = atoi(s_network_num);
    printf("[%s]:New network handle:%d\n",__FUNCTION__, i_network_num);
    //Remove掉这个num之前所有的其他网络，防止影响后续的连接
    for (int i = i_network_num - 1; i >= 0; i--)
    {
        MyShell("wpa_cli -i wlan0 remove_network %d", i);
    }
    MyShell("wpa_cli -i wlan0 save_config");
    
    return i_network_num;
}

void detect_2G(struct NetInfo *structptr)
{
    //配置加密方式,注意，这里写死了
    MyShell("wpa_cli -i wlan0 set_network %d key_mgmt WPA-PSK",structptr->Network_num);

    //配置主网络 2G SSID
    MyShell("wpa_cli -i wlan0 set_network %d ssid '\"%s\"'",structptr->Network_num ,structptr->MAIN_2G_SSID);
    //配置密码
    MyShell("wpa_cli -i wlan0 set_network %d  psk '\"%s\"'", structptr->Network_num, structptr->MAIN_KEY);
    //配置BSSID
    MyShell("wpa_cli -i wlan0 set_network %d bssid %s",structptr->Network_num ,structptr->FAP_2G4_MAC);
    //使能网络，保存配置
    MyShell("wpa_cli -i wlan0 enable_network %d; wpa_cli -i wlan0 save_config", structptr->Network_num);

    ping_status(structptr->GatewayIP);

    MyShell("wpa_cli -i wlan0 disable_network %d",structptr->Network_num);
    sleep(8);
    //配置主网络 5G SSID
    MyShell("wpa_cli -i wlan0 set_network %d ssid '\"%s\"'",structptr->Network_num ,structptr->MAIN_5G_SSID);
    //配置BSSID
    MyShell("wpa_cli -i wlan0 set_network %d bssid %s",structptr->Network_num ,structptr->FAP_5G_MAC);
    //使能网络，保存配置
    MyShell("wpa_cli -i wlan0 enable_network %d; wpa_cli -i wlan0 save_config", structptr->Network_num);

    ping_status(structptr->GatewayIP);
    
}

void detect_5G(struct NetInfo *structptr)
{

}

int main()
{
    //防止多重启动
    AvoidMultiRun();

    //1.初始化一些必要的变量
    struct NetInfo Net_handle;
    memset(&Net_handle, 0,sizeof(Net_handle));
    Init(&Net_handle);

    //2.扫描周围AP,并判断输入的MAC是否存在于周围环境中
    Scan(&Net_handle);

    //3.新增网络
    Net_handle.Network_num = AddNetwork();

    //4.根据所获取的信息配置网络
    //ConfigureNetwork(&Net_handle);

    //睡眠8秒是为了等待树莓派建立完成网络连接
    sleep(8);
    //建立连接,判断能否ping通
    detect_2G(&Net_handle);
    



    //释放文件指针
    close(LOCK_FILE);
    return 0;
}