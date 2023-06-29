package com.bsf.security.validation.password;

import java.util.*;

import com.bsf.security.exception.account.InvalidPasswordAccountException;
import com.bsf.security.exception.account.InvalidPasswordAccountListException;
import org.passay.*;

public class PasswordConstraintValidator {

    public static void isValid(String password) {
        List<Rule> rules = new ArrayList<>();
        rules.add(new LengthRule(8, 16));
        rules.add(new WhitespaceRule());
        rules.add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        rules.add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        rules.add(new CharacterRule(EnglishCharacterData.Digit, 1));
        rules.add(new CharacterRule(EnglishCharacterData.Special, 1));

        PasswordValidator validator = new PasswordValidator(rules);
        RuleResult result = validator.validate(new PasswordData(password));

        List<InvalidPasswordAccountException> exceptions = new ArrayList<>();
        result.getDetails().forEach(ruleResultDetail -> {
            exceptions.add(
                    new InvalidPasswordAccountException(
                            ruleResultDetail.getErrorCode(),
                            ruleResultDetail.getValues()
                    )
            );
        });

        if(!result.isValid()) throw new InvalidPasswordAccountListException(exceptions);
    }

}