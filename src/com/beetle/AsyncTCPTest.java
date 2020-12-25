/*                                                                            
  Copyright (c) 2014-2019, GoBelieve     
    All rights reserved.		    				     			
 
  This source code is licensed under the BSD-style license found in the
  LICENSE file in the root directory of this source tree. An additional grant
  of patent rights can be found in the PATENTS file in the same directory.
*/


package com.beetle;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;



public class AsyncTCPTest extends Activity  {
	AsyncTCPInterface tcp;

	byte[] recvBuf = new byte[0];
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_test);

        Button bt = (Button)findViewById(R.id.button);
        Button bt2 = (Button)findViewById(R.id.button2);
                
        bt.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				test(false);
			}
		});

		bt2.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				test(true);
			}
		});

	}
    
    
    public void test(boolean ssl) {
    	if (tcp != null) return;
    	if (ssl) {
			tcp = new AsyncSSLTCP();
		} else {
			tcp = new AsyncTCP();
		}

    	
    	TCPConnectCallback cb = new TCPConnectCallback() {
    		public void onConnect(Object tcp1, int status) {
    		    if (status != 0) {
    		    	Log.i("Beetle", "connect error");
    		    	tcp.close();
    		    	return;
    		    }
    		    Log.i("Beetle", "connected");
    		    byte[] data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n".getBytes();
    		    tcp.writeData(data);

    		    tcp.startRead();
    		}
    	};
    	TCPReadCallback read_cb = new TCPReadCallback() {
    		public void onRead(Object tcp1, byte[] data) {
    		    if (data.length == 0) {
    		    	try {
    		    		String result = new String(recvBuf, "UTF-8");
    		    		Log.i("Beetle", result);
    		    	} catch(Exception e) {

    		    	}
    		    	Log.i("Beetle", "tcp closed");
    		    	tcp.close();
    		    	tcp = null;
    		    	return;
    		    }
    		    
    		    byte[] result = new byte[recvBuf.length + data.length]; 
		        System.arraycopy(recvBuf, 0, result, 0, recvBuf.length); 
		        System.arraycopy(data, 0, result, recvBuf.length, data.length);
		        recvBuf = result;
    		    Log.i("Beetle", "recv data");
    		}	
    	};

    	tcp.setConnectCallback(cb);
    	tcp.setReadCallback(read_cb);

    	int port = 80;
    	if (ssl) {
    		port = 443;
		}
    	tcp.connect("www.baidu.com", port);
    }
}
