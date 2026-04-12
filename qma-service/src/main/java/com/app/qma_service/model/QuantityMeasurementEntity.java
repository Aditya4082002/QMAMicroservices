package com.app.qma_service.model;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "quantity_measurement")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class QuantityMeasurementEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String operation;
    private String operand1;
    private String operand2;
    private String result;
	private String username;
    
    public QuantityMeasurementEntity(String operation, String operand1, String operand2, String result,String username) {
		this.operation = operation;
		this.operand1 = operand1;
		this.operand2 = operand2;
		this.result = result;
        this.username=username;
		this.createdAt = createdAt;
	}

//	public Long getId() {
//		return id;
//	}
//
//	public String getOperation() {
//		return operation;
//	}
//
//	public void setOperation(String operation) {
//		this.operation = operation;
//	}
//
//	public String getOperand1() {
//		return operand1;
//	}
//
//	public void setOperand1(String operand1) {
//		this.operand1 = operand1;
//	}
//
//	public String getOperand2() {
//		return operand2;
//	}
//
//	public void setOperand2(String operand2) {
//		this.operand2 = operand2;
//	}
//
//	public String getResult() {
//		return result;
//	}
//
//	public void setResult(String result) {
//		this.result = result;
//	}
//
//	public LocalDateTime getCreatedAt() {
//		return createdAt;
//	}
//
//	public void setCreatedAt(LocalDateTime createdAt) {
//		this.createdAt = createdAt;
//	}

	private LocalDateTime createdAt;

    // automatically set timestamp
    @PrePersist
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
