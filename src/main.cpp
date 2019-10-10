#include "main.h"

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

//初始化函数
void Init(NetInfo *structptr)
{
    //防止SF,先赋值

    //判断MAC地址是否合法
    while (1)
    {
        printf("[%s]:Please input your FAP MAC:\n",__FUNCTION__);
        scanf("%s", structptr->FAP_MAC);
        if( CheckMac(structptr->FAP_MAC) == FALSE )
        {
            memset(structptr->FAP_MAC, 0, sizeof(structptr->FAP_MAC));           
        }
        else
            break;
    }

    while (1)
    {
        printf("[%s]:Please input your RE MAC:\n",__FUNCTION__);
        scanf("%s", structptr->RE_MAC);
        if( CheckMac(structptr->RE_MAC) == FALSE )
        {
            memset(structptr->RE_MAC, 0, sizeof(structptr->RE_MAC));   
        }
        else
            break;
    }

    //TBD:记得尝试一下不配置SSID，只配置BSSID能否成功连接
    printf("[%s]:Please input your SSID\n",__FUNCTION__);
    scanf("%s", structptr->SSID);
    printf("[%s]:Please input your KEY\n",__FUNCTION__);
    scanf("%s", structptr->KEY);
}

int main()
{
    //防止多重启动
    AvoidMultiRun();

    //1.初始化(获取信息)
    struct NetInfo Net_handle;
    memset(&Net_handle, 0,sizeof(Net_handle));
    Init(&Net_handle);

    pause();

/*
    //2.扫描周围AP(由于使用的C++的编译工具, void* -> char*需要显式转换
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
            if ( strlen ( (char *)MyShell("wpa_cli -i wlan0 scan_result | grep '%s'", FAP_MAC) )  == 0
                || strlen ( (char *)MyShell("wpa_cli -i wlan0 scan_result | grep '%s'", RE_MAC) )  == 0
               )
            {
                printf("MAC doesn't exist... Retrying \n");
            }
            else
                break;
            
        }
    }

    //3.添加一个网络
    //获取新网络句柄
    char *s_network_num = (char *)MyShell("wpa_cli -i wlan0 add_network");
    int i_network_num = atoi(s_network_num);
    printf("New network handle:%d\n", i_network_num);

    //4.
    // To be done: 以当前的网络句柄为基准，遍历之前的数字，全部disable，保证reconncet的时候不会出bug 

    //5.建立连接
    //配置SSID
    MyShell("wpa_cli -i wlan0 set_network %d ssid '\"%s\"'",i_network_num ,SSID);
    //配置加密方式,注意，这里写死了
    MyShell("wpa_cli -i wlan0 set_network %d key_mgmt WPA-PSK",i_network_num);
    //配置密码
    MyShell("wpa_cli -i wlan0 set_network %d  psk '\"%s\"'", i_network_num, KEY);
    //配置BSSID
    MyShell("wpa_cli -i wlan0 set_network %d bssid %s",i_network_num ,FAP_MAC);
    //使能网络，保存配置
    MyShell("wpa_cli -i wlan0 enable_network %d; wpa_cli -i wlan0 save_config", i_network_num);
*/    
    //释放文件指针
    close(LOCK_FILE);
    return 0;
}