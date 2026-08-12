module tiny_top (
    input  logic [7:0] a,
    input  logic [7:0] b,
    output logic [8:0] y
);
    assign y = {1'b0, a} + {1'b0, b};
endmodule
