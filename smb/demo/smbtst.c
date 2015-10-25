#include "rtp.h"
#include "rtpprint.h"

#include "smbconf.h"

#include "smbtst.h"

#if (INCLUDE_RTSMB_SERVER)
int smbservermain(void);
#endif

#if (INCLUDE_RTSMB_CLIENT)
int smb_cli_test_main (void);
#endif


#ifdef RTSMB_WIN
int main()
{
    char c;

    socket_init ();

    // ------------------------------------------------ 
    do 
    {
        rtp_printf("\n\nRun Server(Y/y) or Client(N/n)");
        while (!kbhit ())
        {       
        }
        c = getch ();
#if (INCLUDE_RTSMB_SERVER)
        if (c == 'Y' || c == 'y')
        {
            smbservermain();
        }
#endif

#if (INCLUDE_RTSMB_CLIENT)
        if (c == 'N' || c == 'n')
        {
            smb_cli_test_main ();
        }
#endif

        if (socket_shutdown() < 0)
        {
            printf("network stack shutdown failed!\n");
            return -1;
        }   
    } while (1);
}
#endif
