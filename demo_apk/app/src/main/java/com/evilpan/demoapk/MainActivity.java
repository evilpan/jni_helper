package com.evilpan.demoapk;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import com.evilpan.demoapk.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;

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
    }
}