let o = {};
let foo = 1;
let a = o.foo === undefined;
o.foo = 1;
let b = o.foo === 1;
a && b && foo + 2 + o.foo === 4;
