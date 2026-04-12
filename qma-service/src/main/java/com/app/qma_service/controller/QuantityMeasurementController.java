package com.app.qma_service.controller;

import com.app.qma_service.dto.QuantityInputDTO;
import com.app.qma_service.dto.QuantityMeasurementDTO;
import com.app.qma_service.service.IQuantityMeasurementService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
//@CrossOrigin(origins = "*")
@RequestMapping("/api/v1/quantities")
public class QuantityMeasurementController {

    @Autowired
    private IQuantityMeasurementService service;
   
    
    //COMPARE
    @PostMapping("/compare")
    public QuantityMeasurementDTO compare(@Valid @RequestBody QuantityInputDTO input,
                                          HttpServletRequest request) {
        String username = request.getHeader("X-User-Name");
        return service.compare(input,username);
    }

    //ADD
    @PostMapping("/add")
    public QuantityMeasurementDTO add(@Valid @RequestBody QuantityInputDTO input,
                                      HttpServletRequest request) {
        String username = request.getHeader("X-User-Name");
        return service.add(input,username);
    }

    //SUBTRACT
    @PostMapping("/subtract")
    public QuantityMeasurementDTO subtract(@Valid @RequestBody QuantityInputDTO input,
                                           HttpServletRequest request) {
        String username = request.getHeader("X-User-Name");
        return service.subtract(input,username);
    }

    //DIVIDE
    @PostMapping("/divide")
    public QuantityMeasurementDTO divide(@Valid @RequestBody QuantityInputDTO input,
                                         HttpServletRequest request) {
        String username = request.getHeader("X-User-Name");
        return service.divide(input,username);
    }

    //CONVERT
    @PostMapping("/convert")
    public QuantityMeasurementDTO convert(@Valid @RequestBody QuantityInputDTO input,
                                          HttpServletRequest request) {
        String username = request.getHeader("X-User-Name");
        return service.convert(input,username);
    }

    //HISTORY
    @GetMapping("/history/{operation}")
    public List<QuantityMeasurementDTO> getHistory(@PathVariable String operation,
                                                   HttpServletRequest request) {
        String username = request.getHeader("X-User-Name");
        return service.getHistoryByOperation(operation,username);
    }

    //COUNT
    @GetMapping("/count/{operation}")
    public long count(@PathVariable String operation) {
        return service.countByOperation(operation);
    }
}