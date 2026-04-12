package com.app.qma_service.dto;

import jakarta.validation.constraints.*;
import lombok.Data;

//@Data
public class QuantityDTO {

    @NotNull(message = "Value cannot be null")
    private Double value;

    @NotBlank(message = "Unit cannot be empty")
    private String unit;

    @NotBlank(message = "Measurement type required")
    @Pattern(
        regexp = "LENGTH|VOLUME|WEIGHT|TEMPERATURE",
        message = "Invalid measurement type"
    )
    private String measurementType;

    @NotBlank(message = "Operation required")
    @Pattern(
        regexp = "ADD|SUBTRACT|DIVIDE|COMPARE|CONVERT",
        message = "Invalid operation"
    )
    private String operation;

	public Double getValue() {
		return value;
	}

	public void setValue(Double value) {
		this.value = value;
	}

	public String getUnit() {
		return unit;
	}

	public void setUnit(String unit) {
		this.unit = unit;
	}

	public String getMeasurementType() {
		return measurementType;
	}

	public void setMeasurementType(String measurementType) {
		this.measurementType = measurementType;
	}

	public String getOperation() {
		return operation;
	}

	public void setOperation(String operation) {
		this.operation = operation;
	}
}
