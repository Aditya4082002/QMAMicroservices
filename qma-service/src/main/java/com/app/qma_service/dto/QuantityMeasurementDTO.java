package com.app.qma_service.dto;

import com.app.qma_service.model.QuantityMeasurementEntity;

import java.time.LocalDateTime;



//@Data
//@NoArgsConstructor
//@AllArgsConstructor

public class QuantityMeasurementDTO {

    private String operation;
    private String operand1;
    private String operand2;
    private String result;

	public String getOperation() {
		return operation;
	}

	public void setOperation(String operation) {
		this.operation = operation;
	}

	public String getOperand1() {
		return operand1;
	}

	public void setOperand1(String operand1) {
		this.operand1 = operand1;
	}

	public String getOperand2() {
		return operand2;
	}

	public void setOperand2(String operand2) {
		this.operand2 = operand2;
	}

	public String getResult() {
		return result;
	}

	public void setResult(String result) {
		this.result = result;
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
		this.success = success;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(LocalDateTime timestamp) {
		this.timestamp = timestamp;
	}

	private boolean success;
    private String errorMessage;

    private LocalDateTime timestamp;

    //convert Entity → DTO
    public static QuantityMeasurementDTO fromEntity(QuantityMeasurementEntity entity) {
    	QuantityMeasurementDTO dto = new QuantityMeasurementDTO();
    	dto.setOperation(entity.getOperation());
    	dto.setOperand1(entity.getOperand1());
    	dto.setOperand2(entity.getOperand2());
    	dto.setResult(entity.getResult());
    	dto.setTimestamp(entity.getCreatedAt());
    	dto.setSuccess(true);

    	return dto;
    }
}
