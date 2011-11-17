package com.netscape.pkisilent;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;


public class PKISilent {
	private static void usage() {
		System.out.print("usage:  java " + PKISilent.class.getCanonicalName());
		boolean first = true;
		for (Class c : classes) {
			if (first) {
				System.out.println(" [ ");
			} else {
				System.out.println(" | ");
			}
			first = false;
			System.out.print("  " + c.getSimpleName());
		}
		System.out.println(" ] ");
	}

	static Class[] classes = { ConfigureCA.class, ConfigureDRM.class,
			ConfigureOCSP.class, ConfigureRA.class, ConfigureSubCA.class,
			ConfigureTKS.class, ConfigureTPS.class, CreateInstance.class, };

	public static final void main(String[] args) {
		HashMap<String, Method> classMap = new HashMap<String, Method>();
		for (Class c : classes) {
			try {
				classMap.put(c.getSimpleName(),
						c.getMethod("main", String[].class));
			} catch (Exception e) {
				// The set of classes listed above is guaranteed to have a
				// method 'main'
				e.printStackTrace();
			}
		}
		if (args.length == 0) {
			usage();
			System.exit(-1);
		}
		Method mainMethod = classMap.get(args[0]);
		if (mainMethod == null) {
			usage();
			System.exit(-1);
		}
		String[] innerArgs = {};
		if (args.length > 1) {
			innerArgs = Arrays.copyOfRange(args, 1, args.length);
		}

		try {
			mainMethod.invoke(null, (Object) innerArgs);
		} catch (Exception e) {
			// exception is guaranteed to have the static main method
		}
	}
}
