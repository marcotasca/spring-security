package com.bsf.security.validation.email;

import java.util.regex.Pattern;

public class EmailConstraintValidator {

    public static boolean isValid(String email) {
        String pattern_RFC_5322 = "^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$";
        return Pattern.compile(pattern_RFC_5322)
                .matcher(email)
                .matches();
    }

}
