package com.johnsonautoparts;

import com.johnsonautoparts.exception.AppException;
import org.owasp.encoder.Encode;

import java.math.BigInteger;
import java.util.Base64;
import java.util.regex.Pattern;

public class TestProject1 {
    private static final Project1 project1 = new Project1(null, null, null);

    public static void main(String[] args) {
//        normalizeString();
//        formatString();
//        validateString();
//        regexClean();
      //  decodeBase64();
        cleanBadHTMLTags();
    }

    private static void normalizeString() {
        String s = "\uFE64" + "script" + "\uFE65";
        String normalizeString = project1.normalizeString(s);
        System.out.println(normalizeString);
    }

    private static void formatString() {
        String s = "%1$tm, %1$te or %1$tY";
        System.out.println(project1.formatString(s));
    }

    private static void validateString() {
        String s1 = "<scr" + "\uFDEF" + "ipt>";
        System.out.println(s1);
        try {
            System.out.println(project1.validateString(s1));
        } catch (AppException e) {
            e.printStackTrace();
        }

        String s2 = "<scr!ipt>";
        System.out.println(s2);
        try {
            System.out.println(project1.validateString(s2));
        } catch (AppException e) {
            e.printStackTrace();
        }
    }

    private static void regularExpression() {
        String search = "(.*? +public\\[\\d+\\] +.*.*)|(.*.*)";
        System.out.println(search);
        search = Pattern.quote(search);
        System.out.println(search);
        String regex = "(.* password\\[\\w+\\]" + search + ".*)";
        System.out.println(regex);
    }

    private static void regexClean() {
        System.out.println(project1.regexClean("<SCRISCRIscriptPTPT>"));
        System.out.println(Encode.forHtml("<SCRIscriptPT>"));
    }

    private static void decodeBase64() {
        BigInteger x = new BigInteger("530500452766");
        byte[] byteArray = x.toByteArray();
        String s = Base64.getEncoder().encodeToString(byteArray);
        System.out.println(project1.decodeBase64(s));
    }

    private static void cleanBadHTMLTags() {
        System.out.println(project1.cleanBadHTMLTags("<script>alert('XSS')</script>"));
        System.out.println(project1.cleanBadHTMLTags("%253Cscript%253Ealert('XSS')%253C%252Fscript%253E"));
    }
}
