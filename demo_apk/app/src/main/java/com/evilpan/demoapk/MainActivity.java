package com.evilpan.demoapk;


import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import com.evilpan.demoapk.databinding.ActivityMainBinding;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        FacadeC fc = new FacadeC();
        FacadeCpp fcc = new FacadeCpp();
        String sb = "=== C ===\n" +
                fc.stringFromJNI() +
                "\n" +
                "dynamic = " + Facade.cDynamic3("hello") +
                "\n" +
                "=== CPP ===\n" +
                fcc.stringFromJNI() + "\n" +
                "dynamic = " + Facade.cppDynamic3("hello") +
                "\n";
        tv.setText(sb);
    }
}
