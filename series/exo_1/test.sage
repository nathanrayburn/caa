p = 14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581  # Example: prime number
g = 11  # Custom number to check

y = Zmod(p)(g)

y_order = y.multiplicative_order()

group_order = y.order()

is_generator = (y_order == group_order)

print(f"The order of the group is: {group_order}")
print(f"The order of g is: {y_order}")
print(f"Is g a generator? {is_generator}")
