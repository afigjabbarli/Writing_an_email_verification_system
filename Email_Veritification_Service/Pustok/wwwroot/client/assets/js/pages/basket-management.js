
function add_to_cart(productId) {
    let url = `basket/add-product/${productId}`

    $.post(url, function (data) {
        console.log(data);
    });
}

function add_to_cart_with_details(productId) {
    let url = `basket/add-product/${productId}`
    let modalElement = $("#quickModal");

    let colorsElement = modalElement.find(".product-details-colors");
    let sizesElement = modalElement.find(".product-details-sizes");
    let quantityElement = modalElement.find(".product-details-quantity");

    var requestData = {
        ColorId: colorsElement.val(),
        SizeId: sizesElement.val(),
        Quantity: quantityElement.val()
    };

    $.post(url, requestData, function (responseData) {
        modalElement.modal('hide');
    });
}

function view_details(productId) {
    let url = `products/${productId}/details`

    $.get(url, function (data) {
        let modalElement = $("#quickModal");
        let nameElement = modalElement.find(".product-details-name");
        let descriptionElement = modalElement.find(".product-details-description");
        let imageElement = modalElement.find(".product-details-image");
        let colorsElement = modalElement.find(".product-details-colors");
        let sizesElement = modalElement.find(".product-details-sizes");
        let addToCartElement = modalElement.find(".product-add-to-cart-button-with-details");

        set_name(nameElement, data);
        set_description(descriptionElement, data);
        set_image(imageElement, data)
        set_colors(colorsElement, data)
        set_sizes(sizesElement, data)

        set_add_to_cart_button(addToCartElement, data);

        modalElement.modal('show');
    });
}

function set_name(element, data) {
    element.html(data["name"])
}

function set_description(element, data) {
    element.html(data["description"])
}

function set_image(element, data) {
    element.attr("src", data["imageUrl"])
}

function set_colors(element, data) {
    element.empty();
    $.each(data["colors"], function (index, colorItem) {
        element.append($('<option>', {
            value: colorItem["id"],
            text: colorItem["name"]
        }));
    });
}

function set_sizes(element, data) {
    element.empty();
    $.each(data["sizes"], function (index, sizeItem) {
        element.append($('<option>', {
            value: sizeItem["id"],
            text: sizeItem["name"]
        }));
    });
}

function set_add_to_cart_button(element, data) {
    element.attr("onclick", `event.preventDefault();add_to_cart_with_details(${data.productId});`)
}


