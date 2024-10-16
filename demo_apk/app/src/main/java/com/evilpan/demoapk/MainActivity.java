package com.evilpan.demoapk;


import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import com.evilpan.demoapk.databinding.ActivityMainBinding;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        FacadeC fc = new FacadeC();
        FacadeCpp fcc = new FacadeCpp();
        String sb = "=== C ===\n" +
                fc.stringFromJNI() +
                "\n" +
                "dynamic = " + fc.testDynamic() +
                "\n" +
                "=== CPP ===\n" +
                fcc.stringFromJNI() + "\n" +
                "dynamic = " + fcc.testDynamic() +
                "\n";
        tv.setText(sb);
        setContentView(tv);
    }
}
