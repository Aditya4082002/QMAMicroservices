package com.app.qma_service.core;

import java.util.Objects;

public class Quantity<U extends Measurable> {

	private final double value;
	private final U unit;

	public Quantity(double value, U unit) {

		if (unit == null) {
			throw new IllegalArgumentException("Unit cannot be null");
		}
		if (!Double.isFinite(value)) {
			throw new IllegalArgumentException("Value must be finite");
		}
		this.value = value;
		this.unit = unit;
	}

	public double getValue() {
		return value;
	}

	public U getUnit() {
		return unit;
	}

	private double convertToBase() {
		return unit.convertToBaseUnit(value);
	}

	// helper method
	private void validateArithematicOperands(Quantity<U> other, U targetUnit, boolean targetUnitRequired) {
		if (other == null) {
			throw new IllegalArgumentException("Unit cannot be null");
		}
		if (!Double.isFinite(value) || !Double.isFinite(other.value)) {
			throw new IllegalArgumentException("Value must be finite");
		}
		if (!this.unit.getClass().equals(other.unit.getClass())) {
			throw new IllegalArgumentException("Different measurement categories.");
		}
		if (targetUnitRequired && targetUnit == null) {
			throw new IllegalArgumentException("Target Unit required.");
		}
	}

	// base arithematic method
	private double performBaseArithematic(Quantity<U> other, ArithematicOperation operation) {

		this.unit.validateOperationSupport(operation.name());
		other.unit.validateOperationSupport(operation.name());

		double base1 = unit.convertToBaseUnit(value);
		double base2 = other.unit.convertToBaseUnit(other.value);

		return operation.compute(base1, base2);

	}

	// Equality

	@Override
	public boolean equals(Object obj) {

		if (this == obj)
			return true;

		if (obj == null || getClass() != obj.getClass())
			return false;

		Quantity<?> other = (Quantity<?>) obj;

		// prevent cross-category comparison
		if (!this.unit.getClass().equals(other.unit.getClass()))
			return false;

		return Double.compare(this.convertToBase(), other.unit.convertToBaseUnit(other.value)) == 0;
	}

	@Override
	public int hashCode() {
		return Objects.hash(convertToBase());
	}

	// Conversion

	public Quantity<U> convertTo(U targetUnit) {

		if (targetUnit == null) {
			throw new IllegalArgumentException("Target unit cannot be null");
		}
		double baseValue = convertToBase();
		double converted = targetUnit.convertFromBaseUnit(baseValue);

		double rounded = Math.round(converted * 100.0) / 100.0;

		return new Quantity<>(rounded, targetUnit);
	}

	// Addition

	public Quantity<U> add(Quantity<U> other) {
		validateArithematicOperands(other, null, false);

		double totalBase = performBaseArithematic(other, ArithematicOperation.ADD);

		double converted = unit.convertFromBaseUnit(totalBase);

		double rounded = Math.round(converted * 100.0) / 100.0;

		return new Quantity<>(rounded, unit);
	}

	public Quantity<U> add(Quantity<U> other, U targetUnit) {

		validateArithematicOperands(other, targetUnit, true);

		double totalBase = performBaseArithematic(other, ArithematicOperation.ADD);

		double converted = targetUnit.convertFromBaseUnit(totalBase);

		double rounded = Math.round(converted * 100.0) / 100.0;

		return new Quantity<>(rounded, targetUnit);
	}

	public Quantity<U> subtract(Quantity<U> other) {

		validateArithematicOperands(other, null, false);

		double result = performBaseArithematic(other, ArithematicOperation.SUBTRACT);

		double converted = unit.convertFromBaseUnit(result);

		double rounded = Math.round(converted * 100.0) / 100.0;
		return new Quantity<>(rounded, unit);
	}

	public Quantity<U> subtract(Quantity<U> other, U targetUnit) {
		validateArithematicOperands(other, targetUnit, true);

		double result = performBaseArithematic(other, ArithematicOperation.SUBTRACT);

		double converted = targetUnit.convertFromBaseUnit(result);

		double rounded = Math.round(converted * 100.0) / 100.0;
		return new Quantity<>(rounded, targetUnit);
	}

	public Quantity<U> divide(Quantity<U> other) {
		validateArithematicOperands(other, null, false);

		double result = performBaseArithematic(other, ArithematicOperation.DIVIDE);

		double converted = unit.convertFromBaseUnit(result);

		double rounded = Math.round(converted * 100.0) / 100.0;
		return new Quantity<>(rounded, unit);
	}

	@Override
	public String toString() {
		return "Quantity(" + value + ", " + unit.getUnitName() + ")";
	}

	// Enum
	private enum ArithematicOperation {
		ADD {
			@Override
			public double compute(double a, double b) {
				return a + b;
			}
		},
		SUBTRACT {

			@Override
			public double compute(double a, double b) {
				return a - b;
			}
		},
		DIVIDE {

			@Override
			public double compute(double a, double b) {
				if (b == 0) {
					throw new ArithmeticException("Divison by zero is not allowed.");
				}
				return a / b;
			}
		};

		public abstract double compute(double a, double b);
	}

}
