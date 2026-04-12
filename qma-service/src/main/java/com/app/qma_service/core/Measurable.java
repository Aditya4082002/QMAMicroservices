package com.app.qma_service.core;

@FunctionalInterface
interface SupportsArithmetic {
    boolean isSupported();
}

public interface Measurable {

    double getConversionFactor();

    double convertToBaseUnit(double value);

    double convertFromBaseUnit(double baseValue);

    String getUnitName();
    // default lambda (all units support arithmetic by default)
    SupportsArithmetic supportsArithmetic = () -> true;

    default boolean supportsArithmetic() {
        return supportsArithmetic.isSupported();
    }

    // validation method (temperature will override this)
    default void validateOperationSupport(String operation) {
        // default: allow all operations
    }

//	Measurable valueOf(String target);
}
